require('dotenv').config();
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();
const port = process.env.PORT || 3000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Raw body for Stripe webhooks, JSON for everything else
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static('.'));

// Declare empty pool variable at top
let pool;

async function getDbPassword() {
  const client = new SecretsManagerClient({ region: 'ap-northeast-2' });
  const response = await client.send(
    new GetSecretValueCommand({ SecretId: process.env.SECRET_ARN })
  );
  const secret = JSON.parse(response.SecretString);
  return secret.password;
}

// Inside initDb, assign it
async function initDb() {
  const password = await getDbPassword();
  
  pool = new Pool({  // ← assign to outer variable!!
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    user: process.env.DB_USER,
    password: password,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false },
  });
  
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      stripe_customer_id TEXT,
      subscribed BOOLEAN DEFAULT FALSE,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS entries (
      id SERIAL PRIMARY KEY,
      date DATE NOT NULL,
      text TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // Add columns if tables already exist without them
  await pool.query(`ALTER TABLE entries ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`);
  // Bootstrap admin from ADMIN_EMAIL env var
  if (process.env.ADMIN_EMAIL) {
    await pool.query(`UPDATE users SET is_admin = TRUE WHERE email = $1`, [process.env.ADMIN_EMAIL.toLowerCase().trim()]);
  }
}

// ── Auth middleware ───────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireSubscription(req, res, next) {
  const result = await pool.query('SELECT subscribed FROM users WHERE id = $1', [req.user.id]);
  if (!result.rows[0] || !result.rows[0].subscribed) {
    return res.status(403).json({ error: 'Active subscription required' });
  }
  next();
}

async function requireAdmin(req, res, next) {
  const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
  if (!result.rows[0] || !result.rows[0].is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ── Auth routes ──────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const normalizedEmail = email.toLowerCase().trim();
    const isAdmin = process.env.ADMIN_EMAIL && normalizedEmail === process.env.ADMIN_EMAIL.toLowerCase().trim();
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, is_admin) VALUES ($1, $2, $3) RETURNING id, email, subscribed, is_admin',
      [normalizedEmail, hash, isAdmin]
    );
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, subscribed: user.subscribed, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const result = await pool.query(
      'SELECT id, email, password_hash, subscribed, is_admin FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, subscribed: user.subscribed, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, email: user.email, subscribed: user.subscribed, is_admin: user.is_admin } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, subscribed, is_admin FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = result.rows[0];
    const newToken = jwt.sign(
      { id: user.id, email: user.email, subscribed: user.subscribed, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ user, token: newToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ── Stripe routes ────────────────────────────────────────────────────
app.post('/api/stripe/checkout', authenticateToken, async (req, res) => {
  try {
    // Get or create Stripe customer
    const userResult = await pool.query('SELECT stripe_customer_id, email FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = $1 WHERE id = $2', [customerId, req.user.id]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${req.headers.origin || 'http://localhost:' + port}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'http://localhost:' + port}`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Verify a completed checkout session (called by frontend on redirect back)
app.post('/api/stripe/verify-session', authenticateToken, async (req, res) => {
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    console.log('Stripe session:', { status: session.status, payment_status: session.payment_status, customer: session.customer });
    const paid = session.payment_status === 'paid' || session.payment_status === 'no_payment_required';
    if ((paid || session.status === 'complete') && session.customer) {
      await pool.query(
        'UPDATE users SET stripe_customer_id = $1, subscribed = TRUE WHERE id = $2',
        [session.customer, req.user.id]
      );
      console.log('User', req.user.id, 'subscription activated');
    }
    const result = await pool.query('SELECT id, email, subscribed, is_admin FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    const newToken = jwt.sign(
      { id: user.id, email: user.email, subscribed: user.subscribed, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ user, token: newToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to verify session' });
  }
});

app.post('/api/stripe/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  // If webhook secret is configured, verify signature; otherwise parse raw body
  if (process.env.STRIPE_WEBHOOK_SECRET && sig) {
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send('Webhook signature verification failed');
    }
  } else {
    event = JSON.parse(req.body);
  }

  if (event.type === 'checkout.session.completed') {
    const customerId = event.data.object.customer;
    await pool.query('UPDATE users SET subscribed = TRUE WHERE stripe_customer_id = $1', [customerId]);
  }

  if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.paused') {
    const customerId = event.data.object.customer;
    await pool.query('UPDATE users SET subscribed = FALSE WHERE stripe_customer_id = $1', [customerId]);
  }

  if (event.type === 'customer.subscription.resumed') {
    const customerId = event.data.object.customer;
    await pool.query('UPDATE users SET subscribed = TRUE WHERE stripe_customer_id = $1', [customerId]);
  }

  res.json({ received: true });
});

// ── Entry routes ─────────────────────────────────────────────────────
// Public: anyone can read
app.get('/api/entries', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, date, text, user_id FROM entries ORDER BY date DESC, created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch entries' });
  }
});

// Protected: logged-in subscribers only
app.post('/api/entries', authenticateToken, requireSubscription, async (req, res) => {
  const { date, text } = req.body;
  if (!date || !text) {
    return res.status(400).json({ error: 'date and text are required' });
  }
  if (text.length > 500) {
    return res.status(400).json({ error: 'Entry must be 500 characters or less' });
  }
  try {
    // Rate limit: max 3 entries per user per day
    const today = new Date().toISOString().slice(0, 10);
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM entries WHERE user_id = $1 AND created_at::date = $2',
      [req.user.id, today]
    );
    if (parseInt(countResult.rows[0].count, 10) >= 3) {
      return res.status(429).json({ error: 'Daily limit reached (3 entries per day)' });
    }
    const result = await pool.query(
      'INSERT INTO entries (date, text, user_id) VALUES ($1, $2, $3) RETURNING id, date, text',
      [date, text, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create entry' });
  }
});

app.delete('/api/entries/:id', authenticateToken, requireSubscription, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid id' });
  }
  try {
    const adminCheck = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    const isAdmin = adminCheck.rows[0] && adminCheck.rows[0].is_admin;
    const entry = await pool.query('SELECT user_id FROM entries WHERE id = $1', [id]);
    if (entry.rows.length === 0) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    if (!isAdmin && entry.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only delete your own entries' });
    }
    await pool.query('DELETE FROM entries WHERE id = $1', [id]);
    res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete entry' });
  }
});

// ── Admin routes ─────────────────────────────────────────────────────
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, subscribed, is_admin, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
  if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  try {
    // Delete user's entries first, then the user
    await pool.query('DELETE FROM entries WHERE user_id = $1', [id]);
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(__dirname + '/admin.html');
});

// ── Start ────────────────────────────────────────────────────────────
initDb()
  .then(() => {
    app.listen(port, '0.0.0.0', () => console.log(`Server running on http://localhost:${port}`));
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
