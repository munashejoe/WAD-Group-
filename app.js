require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const User = require('./models/User');

const app = express();

// Connect to MongoDB
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

// Import the rateLimit package
const rateLimit = require('express-rate-limit');

// Global rate limiter configuration
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false // Disable the `X-RateLimit-*` headers
});

// Registration rate limiter configuration
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 registration attempts per windowMs
  message: { error: 'Too many registration attempts. Try again later.' }, // Custom error message
});

// Exporting the limiters for use in other parts of the application
module.exports = {
  globalLimiter,
  registrationLimiter
};

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

      // Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ 
          success: false,
          error: 'Email already registered' 
        });
      }
      

      // Create new user
      const user = new User({ email, password });
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
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({ success: true, token });
  } catch (error) {
    console.error('Error during login:', error);
    return res.status(500).json({ success: false, error: 'An error occurred during login' });
  }
});

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user._id,
          email: user.email
        }
      });

    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ 
        success: false,
        error: 'Internal server error' 
      });
    }
  }}}
);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

