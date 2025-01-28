require('dotenv').config(); // Load environment variables from .env file
const express = require('express'); // Import Express framework
const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing
const jwt = require('jsonwebtoken'); // Import jsonwebtoken for creating tokens
const rateLimit = require('express-rate-limit'); // Import rate limiter middleware
const { body, validationResult } = require('express-validator'); // Import validation tools
const helmet = require('helmet'); // Import Helmet for security headers

const app = express(); // Initialize Express application

// Middleware to enhance security
app.use(helmet());
app.use(express.json()); // Parse JSON requests
app.use(express.static('public')); // Serve static files from 'public' directory

// Maps to track registration and login attempts
const registrationAttempts = new Map();
const loginAttempts = new Map();

// Global rate limiter for all requests
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per window
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false // Disable the `X-RateLimit-*` headers
});

// Rate limiter for registration requests
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit to 5 registrations per hour
  message: { error: 'Too many registration attempts. Try again later.' }, // Error message
  keyGenerator: (req) => req.ip // Use IP address as key
});

// Rate limiter for login requests
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit to 10 login attempts per window
  message: { error: 'Too many login attempts. Try again later.' } // Error message
});

// Apply the global rate limiter to all routes
app.use(globalLimiter);

// In-memory user database (replace with persistent database in production)
let users = [];

// Registration endpoint
app.post('/api/register', 
  registrationLimiter, // Apply registration rate limiter
  [
    // Validation rules for email and password
    body('email')
      .isEmail().withMessage('Invalid email format') // Check for valid email format
      .normalizeEmail(), // Normalize email
    body('password')
      .isLength({ min: 12 }).withMessage('Password must be at least 12 characters') // Check password length
      .matches(/[0-9]/).withMessage('Password must contain a number') // Check for number
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter') // Check for uppercase letter
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter') // Check for lowercase letter
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain a special character') // Check for special character
  ],
  async (req, res) => {
    try {
      // Validate request body
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() }); // Return validation errors
      }

      const { email, password } = req.body;

      // Check if user already exists
      if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' }); // Return error if email exists
      }

      // Hash the password before saving
      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser = {
        id: Date.now(), // Use timestamp as user ID
        email,
        password: hashedPassword,
        registrationIP: req.ip // Store registration IP
      };
      users.push(newUser); // Add user to in-memory database

      // Respond with success message
      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        user: {
          id: newUser.id,
          email: newUser.email
        }
      });

    } catch (err) {
      console.error('Registration error:', err); // Log error
      res.status(500).json({ error: 'Internal server error' }); // Return server error
    }
  }
);

// Login endpoint
app.post('/api/login', 
  loginLimiter, // Apply login rate limiter
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = users.find(u => u.email === email); // Find user by email
      
      // Check if user exists and password matches
      if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' }); // Return unauthorized error
      }

      // Create JWT token
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { 
        expiresIn: '1h' // Set token expiration to 1 hour
      });

      // Respond with token and user info
      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email
        }
      });

    } catch (err) {
      console.error('Login error:', err); // Log error
      res.status(500).json({ error: 'Internal server error' }); // Return server error
    }
  }
);

// Start the server
const PORT = process.env.PORT || 3000; // Use port from environment variable or default to 3000
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`); // Log server start
});
