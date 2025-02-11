require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const User = require('./models/User');

const app = express();

// Connect to MongoDB and see
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected successfully.');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

app.use(helmet());
app.use(express.json());
app.use(express.static('public'));

// Global rate limiter configuration
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per windowMs and see
  standardHeaders: true,
  legacyHeaders: false
});

// Registration rate limiter configured and see
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { error: 'Too many registration attempts. Try again later.' },
});

// Login rate limiter configuration
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts. Try again later.' },
});

app.use(globalLimiter);

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
        return res.status(400).json({ 
          success: false,
          errors: errors.array() 
        });
      }

      const { email, password } = req.body;

      // Check if user exists and see
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ 
          success: false,
          error: 'Email already registered' 
        });
      }

      // Hash password and see
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create new user and see
      const user = new User({ email, password: hashedPassword });
      await user.save();

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        user: {
          id: user._id,
          email: user.email
        }
      });

    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ 
        success: false,
        error: 'Internal server error' 
      });
    }
  }
);

// Login endpoint
app.post('/api/login', 
  loginLimiter,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // Find user
      const user = await User.findOne({ email });
      
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid credentials' 
        });