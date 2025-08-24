const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'abstract-dev-test-bank-orm';

const dbPath = path.join(__dirname, 'bank.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    account_number TEXT UNIQUE NOT NULL,
    name TEXT DEFAULT 'Основной счет',
    balance REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    from_account TEXT NOT NULL,
    to_account TEXT NOT NULL,
    amount REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_account) REFERENCES accounts (account_number),
    FOREIGN KEY (to_account) REFERENCES accounts (account_number)
  )`);
});

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const generateAccountNumber = () => {
  return 'LI' + Array.from({length: 16}, () => Math.floor(Math.random() * 10)).join('') + 'SP';
};

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (row) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = uuidv4();
      
      db.run('INSERT INTO users (id, username, password) VALUES (?, ?, ?)', 
        [userId, username, hashedPassword], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          const accountId = uuidv4();
          const accountNumber = generateAccountNumber();
          
          db.run('INSERT INTO accounts (id, user_id, account_number, name, balance) VALUES (?, ?, ?, ?, ?)', 
            [accountId, userId, accountNumber, 'Основной счет', 0], function(err) {
              if (err) {
                return res.status(500).json({ error: 'Failed to create account' });
              }
              
              res.status(201).json({ message: 'Account created' });
            });
        });
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    db.all('SELECT * FROM accounts WHERE user_id = ? AND is_active = 1', [user.id], (err, accounts) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to get accounts' });
      }
      
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({ 
        token,
        accounts: accounts.map(acc => ({
          id: acc.id,
          accountNumber: acc.account_number,
          name: acc.name,
          balance: acc.balance
        }))
      });
    });
  });
});

app.get('/accounts', authenticateToken, (req, res) => {
  db.all('SELECT * FROM accounts WHERE user_id = ? AND is_active = 1', [req.user.userId], (err, accounts) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to get accounts' });
    }
    
    res.json(accounts.map(acc => ({
      id: acc.id,
      accountNumber: acc.account_number,
      name: acc.name,
      balance: acc.balance,
      createdAt: acc.created_at
    })));
  });
});

app.post('/accounts/create', authenticateToken, (req, res) => {
  const { name } = req.body;
  
  db.get('SELECT COUNT(*) as count FROM accounts WHERE user_id = ? AND is_active = 1', 
    [req.user.userId], (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (row.count >= 5) {
        return res.status(400).json({ error: 'Maximum account limit reached (5 accounts)' });
      }
      
      const accountId = uuidv4();
      const accountNumber = generateAccountNumber();
      const accountName = name || `Счет ${row.count + 1}`;
      
      db.run('INSERT INTO accounts (id, user_id, account_number, name, balance) VALUES (?, ?, ?, ?, ?)', 
        [accountId, req.user.userId, accountNumber, accountName, 0], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create account' });
          }
          
          res.json({ 
            message: 'Account created successfully',
            account: {
              id: accountId,
              accountNumber: accountNumber,
              name: accountName,
              balance: 0
            }
          });
        });
    });
});

app.put('/accounts/:accountId/name', authenticateToken, (req, res) => {
  const { accountId } = req.params;
  const { name } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Account name cannot be empty' });
  }
  
  db.get('SELECT * FROM accounts WHERE id = ? AND user_id = ?', 
    [accountId, req.user.userId], (err, account) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!account) {
        return res.status(404).json({ error: 'Account not found' });
      }

      db.run('UPDATE accounts SET name = ? WHERE id = ?', [name, accountId], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update account name' });
        }
        
        res.json({ message: 'Account name updated successfully' });
      });
    });
});

app.delete('/accounts/:accountId', authenticateToken, (req, res) => {
  const { accountId } = req.params;

  db.get('SELECT * FROM accounts WHERE id = ? AND user_id = ?', 
    [accountId, req.user.userId], (err, account) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!account) {
        return res.status(404).json({ error: 'Account not found' });
      }
      
      if (account.balance > 0) {
        return res.status(400).json({ error: 'Cannot delete account with balance' });
      }

      db.run('UPDATE accounts SET is_active = 0 WHERE id = ?', [accountId], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to delete account' });
        }
        
        res.json({ message: 'Account deleted successfully' });
      });
    });
});

app.post('/transfer', authenticateToken, (req, res) => {
  const { fromAccount, toAccount, amount } = req.body;

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    db.get('SELECT * FROM accounts WHERE account_number = ? AND is_active = 1', 
      [toAccount], (err, toAcc) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (!toAcc) {
          db.run('ROLLBACK');
          return res.status(400).json({ error: 'Recipient account not found' });
        }

        db.get('SELECT * FROM accounts WHERE account_number = ? AND user_id = ? AND is_active = 1', 
          [fromAccount, req.user.userId], (err, fromAcc) => {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Database error' });
            }
            
            if (!fromAcc) {
              db.run('ROLLBACK');
              return res.status(400).json({ error: 'Invalid sender account' });
            }
            
            if (fromAcc.balance < amount) {
              db.run('ROLLBACK');
              return res.status(400).json({ error: 'Insufficient funds' });
            }

            db.run('UPDATE accounts SET balance = balance - ? WHERE account_number = ?', 
              [amount, fromAccount], function(err) {
                if (err) {
                  db.run('ROLLBACK');
                  return res.status(500).json({ error: 'Failed to update sender balance' });
                }
                
                db.run('UPDATE accounts SET balance = balance + ? WHERE account_number = ?', 
                  [amount, toAccount], function(err) {
                    if (err) {
                      db.run('ROLLBACK');
                      return res.status(500).json({ error: 'Failed to update recipient balance' });
                    }

                    const transactionId = uuidv4();
                    db.run('INSERT INTO transactions (id, from_account, to_account, amount) VALUES (?, ?, ?, ?)', 
                      [transactionId, fromAccount, toAccount, amount], function(err) {
                        if (err) {
                          db.run('ROLLBACK');
                          return res.status(500).json({ error: 'Failed to record transaction' });
                        }
                        
                        db.run('COMMIT');

                        db.get('SELECT balance FROM accounts WHERE account_number = ?', 
                          [fromAccount], (err, row) => {
                            if (err) {
                              return res.status(500).json({ error: 'Failed to get updated balance' });
                            }
                            
                            res.json({ 
                              message: 'Transfer successful', 
                              newBalance: row.balance 
                            });
                          });
                      });
                  });
              });
          });
      });
  });
});

app.get('/transactions', authenticateToken, (req, res) => {

  db.all('SELECT account_number FROM accounts WHERE user_id = ? AND is_active = 1', 
    [req.user.userId], (err, accounts) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to get accounts' });
      }
      
      const accountNumbers = accounts.map(acc => acc.account_number);
      const placeholders = accountNumbers.map(() => '?').join(',');

      db.all(`SELECT * FROM transactions WHERE from_account IN (${placeholders}) OR to_account IN (${placeholders}) ORDER BY timestamp DESC`, 
        [...accountNumbers, ...accountNumbers], (err, transactions) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to get transactions' });
          }
          
          res.json(transactions);
        });
    });
});

app.get('/account/:accountNumber', authenticateToken, (req, res) => {
  const { accountNumber } = req.params;
  
  db.get('SELECT * FROM accounts WHERE account_number = ? AND user_id = ? AND is_active = 1', 
    [accountNumber, req.user.userId], (err, account) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!account) {
        return res.status(404).json({ error: 'Account not found' });
      }
      
      res.json({
        accountNumber: account.account_number,
        name: account.name,
        balance: account.balance
      });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));