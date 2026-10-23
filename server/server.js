const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');

dotenv.config();
connectDB();

const app = express();
app.use(express.json());

// Test route - Week 1 Identity Layer
app.post('/api/auth/register', async (req, res) => {
  try {
    const User = require('./models/User');
    const Profile = require('./models/Profile');
    
    const { username, email, password } = req.body;
    
    // Create User - password will auto-hash with salt 12
    const user = await User.create({ username, email, password });
    
    // Create linked Profile
    const profile = await Profile.create({ user: user._id });
    
    res.status(201).json({
      success: true,
      message: 'User created - Week 1 complete',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
        // password NOT returned - type-safety working!
      },
      profileId: profile._id
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.get('/', (req, res) => res.send('Week 1 Secure Wallet API Running'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server on ${PORT}`));