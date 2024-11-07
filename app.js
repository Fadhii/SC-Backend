const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();

const app = express();
connectDB();

app.use(express.json());
app.use('/api/auth', authRoutes);

app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

module.exports = app;
