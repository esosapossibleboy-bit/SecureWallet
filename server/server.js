const express = require('express');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const connectDB = require('./config/db');
const { mongo } = require('mongoose');

dotenv.config();
connectDB();

const app = express();

// ===== WEEK 2 SECURITY STACK =====

// 1. Helmet.js - security headers
app.use(helmet());

// 2. CORS strict origins (zero-trust)
app.use(cors({
  origin: 'http://localhost:3000', // only allow your frontend
  credentials: true
}));

// 3. Body parser + cookie parser
app.use(express.json());
app.use(cookieParser());

// 4. Sanitize against NoSQL injection ($gt attacks)
app.use((req, res, next) => {
  if (req.body) {
    mongoSanitize.sanitize(req.body);
  }
  if (req.params) {
    mongoSanitize.sanitize(req.params);
  }
  // Skip req.query - Express 5 makes it read-only
  next();
}); 

// 5. Rate limiting - throttle brute-force
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 100, // limit each IP to 100 requests
  message: 'Too many requests, try again later',
  standardHeaders: true,
});
app.use('/api/', limiter);

// Stricter limit for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // only 5 login attempts per 15 mins
  message: 'Too many login attempts, account locked for 15 mins'
});

// ===== WEEK 2 AUTH LOGIC =====

const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Profile = require('./models/Profile');

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'supersecret_fallback_change_me', {
    expiresIn: '7d'
  });
};

// REGISTER (Week 1 code + HTTP-only cookie)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = await User.create({ username, email, password });
    await Profile.create({ user: user._id });

    const token = generateToken(user._id);

    // HTTP-only cookie injection - Week 2 core deliverable
    res.cookie('token', token, {
      httpOnly: true, // JS cannot access - XSS protection
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      success: true,
      message: 'User created - Week 1 complete',
      user: { id: user._id, username: user.username, email: user.email }
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// LOGIN - New for Week 2
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    
    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const token = generateToken(user._id);
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ success: true, message: 'Login successful - Zero-Trust session created' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PROTECTED ROUTE TEST - Zero-Trust verification
app.get('/api/me', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'No token - Zero-Trust blocked' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecret_fallback_change_me');
    const user = await User.findById(decoded.id);
    
    res.json({ success: true, user: { id: user._id, email: user.email } });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/', (req, res) => res.send('Week 2 Zero-Trust API Running - Helmet + RateLimit + httpOnly'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Week 2 Secure Server on ${PORT}`));