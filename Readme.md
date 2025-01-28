# Secure RESTful API Demo

A demonstration of secure API practices with Express.js

## Key Security Features
🔒 **Authentication**  
- JWT tokens with 1-hour expiration
- Password hashing using bcrypt (10 rounds)

🛡️ **Protections**  
- Rate limiting (100 requests/15 minutes per IP)
- Security headers (X-Content-Type-Options, X-Frame-Options)
- Input validation/sanitization
- CORS origin restrictions

⚠️ **Development Limitations**  
- In-memory database (users array)
- HTTP only (no HTTPS)
- No CSRF protection
- No refresh token rotation

## Getting Started
1. Install dependencies:
```bash
npm install express bcryptjs jsonwebtoken dotenv express-rate-limit express-validator