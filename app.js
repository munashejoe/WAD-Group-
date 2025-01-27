require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(express.static('public'));

// Tracking registrations and login attempts
const registrationAttempts = new Map();
const loginAttempts = new Map();

// Rate limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per window
  standardHeaders: true,
  legacyHeaders: false
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour
  message: { error: 'Too many registration attempts. Try again later.' },
  keyGenerator: (req) => req.ip
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per window
  message: { error: 'Too many login attempts. Try again later.' }
});

app.use(globalLimiter);

// In-memory database (replace with persistent database in production)
let users = [];

// Registration endpoint
app.post('/api/register', 
  registrationLimiter,
  [
    body('email')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 12 }).withMessage('Password must be at least 12 characters')
      .matches(/[0-9]/).withMessage('Password must contain a number')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain a special character')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      // Check if user already exists
      if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser = {
        id: Date.now(),
        email,
        password: hashedPassword,
        registrationIP: req.ip
      };
      users.push(newUser);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        user: {
          id: newUser.id,
          email: newUser.email
        }
      });

    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Login endpoint
app.post('/api/login', 
  loginLimiter,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = users.find(u => u.email === email);
      
      if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { 
        expiresIn: '1h'
      });

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email
        }
      });

    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
