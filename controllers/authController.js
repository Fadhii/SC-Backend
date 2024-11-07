const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const generateOTP = require('../utils/generateOTP');
require('dotenv').config();

exports.signup = async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 mins
        const user = new User({ email, password, otp, otpExpires });
        await user.save();

        console.log(`Your OTP is: ${otp}`); // Logs OTP to the console
        res.status(201).json({ message: 'OTP sent to console' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

exports.signin = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        console.log('User found:', user);

        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        console.log('Password match:', isMatch);

        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        if (!user.verified) {
            console.log('User not verified');
            return res.status(403).json({ message: 'Account not verified' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('JWT token:', token);
        res.json({ token });
    } catch (err) {
        console.error('Sign-in error:', err); // Log full error for debugging
        res.status(500).json({ error: 'Server error' });
    }
};


exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email, otp, otpExpires: { $gt: new Date() } });
        if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

        user.otp = undefined;
        user.otpExpires = undefined;
        user.verified = true;
        await user.save();

        res.json({ message: 'Account verified successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

exports.resendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const otp = generateOTP();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        console.log(`Your new OTP is: ${otp}`); // Logs OTP to the console
        res.json({ message: 'New OTP sent to console' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};
