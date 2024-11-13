const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const UserDetails = require('../models/userDetails'); // Ensure correct import

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

// Signin function: returns accessToken and refreshToken
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
            httpOnly: true,    // Can't be accessed via JavaScript
            secure: process.env.NODE_ENV === 'production',  // Set to true in production
            maxAge: 15 * 60 * 1000,  // Token expires in 15 minutes
            sameSite: 'Strict'   // Prevents CSRF attacks
        });

        // Set the refreshToken as a secure cookie (optional)
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,    // Can't be accessed via JavaScript
            secure: process.env.NODE_ENV === 'production',  // Set to true in production
            maxAge: 7 * 24 * 60 * 60 * 1000,  // Refresh token expires in 7 days
            sameSite: 'Strict'   // Prevents CSRF attacks
        });

        res.status(200).json({
            message: 'Signin successful. Tokens are stored as cookies.'
        });
    } catch (err) {
        console.error("Error during signin:", err);
        res.status(500).json({ error: 'Server error' });
    }
};

// Refresh access token using refresh token
// Refresh access token using refresh token from cookies
exports.refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken; // Get the refresh token from cookies

        if (!refreshToken) {
            return res.status(400).json({ message: 'Refresh token is required' });
        }

        // Verify the refresh token
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired refresh token' });
            }

            // Find the user associated with the refresh token
            const user = await User.findById(decoded.userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Create a new access token
            const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });

            // Set the new access token as a secure HttpOnly cookie
            res.cookie('accessToken', accessToken, {
                httpOnly: true, // Can't be accessed via JavaScript
                secure: process.env.NODE_ENV === 'production', // Set to true in production
                maxAge: 15 * 60 * 1000, // Token expires in 15 minutes
                sameSite: 'Strict' // Prevents CSRF attacks
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
        const { fullname, address, dateofbirth, email, mobile, gender, housename, landmark, pincode, district, state, profileImage } = req.body;

        // Get the access token from cookies
        const token = req.cookies.accessToken;

        if (!token) {
            return res.status(401).json({ message: 'Access token is required' });
        }

        // Verify the access token
        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired token' });
            }

            const userId = decoded.userId;
            const user = await User.findById(userId);

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Check if user details already exist in the userdetails collection
            let userDetails = await UserDetails.findOne({ userId });

            if (!userDetails) {
                // If no user details found, create a new entry
                userDetails = new UserDetails({
                    userId,
                    fullname,
                    address,
                    dateofbirth,
                    email,
                    mobile,
                    gender,
                    housename,
                    landmark,
                    pincode,
                    district,
                    state,
                    profileImage,
                });
            } else {
                // If user details already exist, update them
                userDetails.fullname = fullname || userDetails.fullname;
                userDetails.address = address || userDetails.address;
                userDetails.dateofbirth = dateofbirth || userDetails.dateofbirth;
                userDetails.email = email || userDetails.email;
                userDetails.mobile = mobile || userDetails.mobile;
                userDetails.gender = gender || userDetails.gender;
                userDetails.housename = housename || userDetails.housename;
                userDetails.landmark = landmark || userDetails.landmark;
                userDetails.pincode = pincode || userDetails.pincode;
                userDetails.district = district || userDetails.district;
                userDetails.state = state || userDetails.state;
                userDetails.profileImage = profileImage || userDetails.profileImage;
            }

            // Save the user details to the database
            await userDetails.save();

            return res.status(200).json({ message: 'Profile updated successfully' });
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
};
