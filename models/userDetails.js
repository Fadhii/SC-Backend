const mongoose = require('mongoose');

const userDetailsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fullname: { type: String, required: true },
    address: { type: String, required: true },
    dateofbirth: { type: Date, required: true },
    email: { type: String, required: true },
    mobile: { type: String, required: true },
    gender: { type: String, required: true },
    housename: { type: String, required: true },
    landmark: { type: String, required: true },
    pincode: { type: String, required: true },
    district: { type: String, required: true },
    state: { type: String, required: true },
    profileImage: { type: String, required: false },
}, { timestamps: true });

const UserDetails = mongoose.model('UserDetails', userDetailsSchema);

module.exports = UserDetails;
