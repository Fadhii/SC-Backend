const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const UserDetails = require('../models/userDetails'); // Ensure correct import

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const tempOTPs = {}; // Temporarily store OTPs, passwords, and expiry times

// Helper function to generate a 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Signup function
exports.signup = async (req, res) => {
    try {
        const { email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        const otp = generateOTP();
        tempOTPs[email] = { otp, password, otpExpires: Date.now() + 10 * 60 * 1000 };

        console.log(`Your OTP is: ${otp}`); // Log OTP to console for demonstration purposes
        res.status(201).json({ message: 'OTP sent to console' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Verify OTP and create user if OTP is valid
exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const tempData = tempOTPs[email];

        if (!tempData || tempData.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP expired or invalid' });
        }

        if (tempData.otp !== otp) {
            return res.status(400).json({ message: 'Incorrect OTP' });
        }

        // OTP is correct; create the user in the database
        const hashedPassword = await bcrypt.hash(tempData.password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();

        delete tempOTPs[email]; // Remove OTP data after successful verification

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Resend OTP if needed
exports.resendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const tempData = tempOTPs[email];

        if (!tempData) return res.status(400).json({ message: 'No OTP request found for this email' });

        const otp = generateOTP();
        tempOTPs[email] = { ...tempData, otp, otpExpires: Date.now() + 10 * 60 * 1000 };

        console.log(`Your new OTP is: ${otp}`); // Log new OTP to console for demonstration
        res.json({ message: 'New OTP sent to console' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Signin function: returns accessToken and refreshToken for email login
exports.signin = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT accessToken
        const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });

        // Generate refreshToken
        const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        // Set the accessToken as a secure, HttpOnly cookie
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 15 * 60 * 1000,
            sameSite: 'Strict'
        });

        // Set the refreshToken as a secure cookie (optional)
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            sameSite: 'Strict'
        });

        res.status(200).json({ message: 'Signin successful. Tokens are stored as cookies.' });
    } catch (err) {
        console.error("Error during signin:", err);
        res.status(500).json({ error: 'Server error' });
    }
};

exports.googleLogin = async (req, res) => {
    try {
        // Retrieve the id_token from the request body
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: 'ID Token is required' });
        }

        // Verify the ID token with Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        
        // Extract payload containing user info
        const payload = ticket.getPayload();
        const { email, name, picture } = payload;

        // Check if user exists in our database
        let user = await User.findOne({ email });
        if (!user) {
            // Create a new user if none exists
            user = new User({ email, name, picture });
            await user.save();
        }

        // Generate access and refresh tokens for the user
        const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        // Set tokens as cookies or send in response
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 15 * 60 * 1000,
            sameSite: 'Strict',
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            sameSite: 'Strict',
        });

        res.status(200).json({ message: 'Google login successful', user });
    } catch (error) {
        console.error('Error in Google login:', error);
        res.status(500).json({ message: 'Google login failed' });
    }
};

// Refresh access token using refresh token
exports.refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(400).json({ message: 'Refresh token is required' });
        }

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired refresh token' });
            }

            const user = await User.findById(decoded.userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
            res.cookie('accessToken', accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 15 * 60 * 1000,
                sameSite: 'Strict'
            });

            return res.status(200).json({ message: 'New access token has been set in cookies' });
        });
    } catch (err) {
        console.error("Error during token refresh:", err);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

// Handle profile filling
exports.fillYourProfile = async (req, res) => {
    try {
        const { fullname, address, dateofbirth, gender, userId } = req.body;

        const userDetails = new UserDetails({ fullname, address, dateofbirth, gender, user: userId });
        await userDetails.save();

        res.status(200).json({ message: 'Profile filled successfully' });
    } catch (err) {
        console.error("Error during profile update:", err);
        res.status(500).json({ error: 'Profile filling failed' });
    }
};
