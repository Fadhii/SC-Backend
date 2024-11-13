const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Signup route
router.post('/signup', authController.signup);

// OTP verification route
router.post('/verify-otp', authController.verifyOtp);

// Resend OTP
router.post('/resend-otp', authController.resendOtp);

// Google login route
router.post('/google', authController.googleLogin);

// Signin route
router.post('/signin', authController.signin);

// Refresh token route
router.post('/refresh-token', authController.refreshAccessToken);

// Profile update route
router.post('/fill-profile', authController.fillYourProfile);

module.exports = router;
