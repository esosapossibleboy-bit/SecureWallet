const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Min 3 chars'],
    maxlength: [30, 'Max 30 chars'],
    match: [/^[a-zA-Z0-9_]+$/, 'Only alphanumeric & underscore allowed'] // regex validation
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email format'] // regex validation
  },
  password: {
    type: String,
    required: [true, 'Password required'],
    minlength: [8, 'Min 8 chars'],
    select: false // type-safety: never return password by default
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true // type-safety: cannot be overwritten
  }
}, {
  timestamps: true
});

// Bcrypt hashing - Salt Rounds: 12 (as per your roadmap)
UserSchema.pre('save', async function() {
  if (!this.isModified('password')) return next;
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare password
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);