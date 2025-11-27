const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ------- Database Connection -------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

// ------- Initialize DB -------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      identifier TEXT UNIQUE,
      salt TEXT,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS vaults (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id),
      ciphertext BYTEA,
      iv BYTEA,
      version INT DEFAULT 1,
      updated_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS ledger (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id),
      prev_hash TEXT,
      block_hash TEXT,
      timestamp TIMESTAMP DEFAULT now()
    );
  `);
}
initDb();

// ========== AUTH ==========
app.post('/auth/register', async (req, res) => {
  const { identifier, salt } = req.body;
  if (!identifier || !salt)
    return res.status(400).json({ error: 'missing_fields' });

  try {
    const id = uuidv4();
    await pool.query(
      'INSERT INTO users (id, identifier, salt) VALUES ($1, $2, $3)',
      [id, identifier, salt]
    );

    const token = jwt.sign({ id, identifier }, JWT_SECRET);
    return res.json({ token, id });
  } catch (err) {
    return res.status(500).json({ error: 'server_error', details: err });
  }
});

app.post('/auth/login', async (req, res) => {
  const { identifier } = req.body;
  if (!identifier)
    return res.status(400).json({ error: 'missing_identifier' });

  const result = await pool.query(
    'SELECT id, salt FROM users WHERE identifier = $1',
    [identifier]
  );

  if (result.rows.length === 0)
    return res.status(404).json({ error: 'not_found' });

  const user = result.rows[0];
  const token = jwt.sign({ id: user.id, identifier }, JWT_SECRET);

  return res.json({ token, salt: user.salt, id: user.id });
});

// ========== VAULT ==========

app.post('/vault/save', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ error: 'no_auth_header' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const { ciphertextBase64, ivBase64 } = req.body;
    if (!ciphertextBase64 || !ivBaseBase64)
      return res.status(400).json({ error: 'missing_fields' });

    const userId = decoded.id;

    const update = await pool.query(
      `
      INSERT INTO vaults (id, user_id, ciphertext, iv, version)
      VALUES ($1, $2, $3, $4, 1)
      ON CONFLICT (user_id)
      DO UPDATE SET
        ciphertext = EXCLUDED.ciphertext,
        iv = EXCLUDED.iv,
        version = vaults.version + 1,
        updated_at = now()
      RETURNING version;
      `,
      [
        uuidv4(),
        userId,
        Buffer.from(ciphertextBase64, 'base64'),
        Buffer.from(ivBase64, 'base64')
      ]
    );

    res.json({ ok: true, version: update.rows[0].version });
  } catch (error) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

app.get('/vault/get', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ error: 'no_auth_header' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      'SELECT ciphertext, iv FROM vaults WHERE user_id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0)
      return res.json({ found: false });

    const row = result.rows[0];

    return res.json({
      found: true,
      ciphertextBase64: row.ciphertext?.toString('base64'),
      ivBase64: row.iv?.toString('base64')
    });
  } catch (error) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ------- Start Server -------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
