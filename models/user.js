const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false }  // Password is optional for Google login
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
