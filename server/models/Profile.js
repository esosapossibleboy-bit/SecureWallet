const mongoose = require('mongoose');

const ProfileSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  fullName: {
    type: String,
    trim: true,
    match: [/^[a-zA-Z\s]+$/, 'Only letters allowed']
  },
  phone: {
    type: String,
    match: [/^\+?[0-9]{10,15}$/, 'Invalid phone format']
  },
  kycVerified: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

module.exports = mongoose.model('Profile', ProfileSchema);