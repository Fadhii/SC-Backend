const mongoose = require('mongoose');

const userDetailsSchema = new mongoose.Schema({
    fullname: { type: String, required: true },
    address: { type: String, required: true },
    dateofbirth: { type: Date, required: true },
    gender: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

module.exports = mongoose.model('UserDetails', userDetailsSchema);
