const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Signup route to create a new user
router.post('/signup', authController.signup);

// OTP verification route
router.post('/verify-otp', authController.verifyOtp);

// Resend OTP route
router.post('/resend-otp', authController.resendOtp);

// Signin route to receive access and refresh tokens
router.post('/signin', authController.signin);

// Refresh access token route
router.post('/refresh-token', authController.refreshAccessToken);

// Profile update route
router.post('/fill-profile', authController.fillYourProfile);

module.exports = router;
