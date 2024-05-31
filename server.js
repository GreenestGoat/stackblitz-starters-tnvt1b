// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const db = new sqlite3.Database('database.db');

// Create accounts table
db.run(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    api_key TEXT
  )
`);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Middleware to check API key
app.use('/icons.js', (req, res, next) => {
  const apiKey = req.query.api;
  if (!apiKey) {
    return res.status(401).json({ error: 'API key missing' });
  }

  db.get('SELECT * FROM accounts WHERE api_key = ?', [apiKey], (err, row) => {
    if (err || !row) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  });
});

app.get('/', (req, res) => {
  const username = req.cookies.username;
  let apiKey = null;

  db.get(
    'SELECT api_key FROM accounts WHERE username = ?',
    [username],
    (err, row) => {
      if (!err && row) {
        apiKey = row.api_key;
      }
      res.render('index', { username, apiKey });
    }
  );
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Check password requirements
  if (
    password.length < 5 ||
    !/[A-Z]/.test(password) ||
    !/[!@#$%^&*(),.?":{}|<>]/.test(password)
  ) {
    return res.redirect('/');
  }

  db.run(
    'INSERT INTO accounts (username, password) VALUES (?, ?)',
    [username, password],
    function (err) {
      if (err) {
        return res.redirect('/');
      }
      res.cookie('username', username, { maxAge: 24 * 60 * 60 * 1000 }); // 24 hours
      res.redirect('/');
    }
  );
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(
    'SELECT * FROM accounts WHERE username = ?',
    [username],
    (err, row) => {
      if (err || !row || row.password !== password) {
        return res.redirect('/');
      }
      res.cookie('username', username, { maxAge: 24 * 60 * 60 * 1000 }); // 24 hours
      res.redirect('/');
    }
  );
});

app.post('/api-key', (req, res) => {
  const username = req.cookies.username;
  if (!username) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.get(
    'SELECT api_key FROM accounts WHERE username = ?',
    [username],
    (err, row) => {
      if (err || !row) {
        return res.status(500).json({ error: 'Internal server error' });
      }

      let apiKey = row.api_key;
      if (!apiKey) {
        apiKey = crypto.randomBytes(6).toString('hex');
        db.run(
          'UPDATE accounts SET api_key = ? WHERE username = ?',
          [apiKey, username],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ apiKey });
          }
        );
      } else {
        apiKey = crypto.randomBytes(6).toString('hex');
        db.run(
          'UPDATE accounts SET api_key = ? WHERE username = ?',
          [apiKey, username],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ apiKey });
          }
        );
      }
    }
  );
});

app.get('/logout', (req, res) => {
  res.clearCookie('username');
  res.redirect('/');
});

app.get('/icons.js', (req, res) => {
  res.sendFile(__dirname + '/icons.js');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
