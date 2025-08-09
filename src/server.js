require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { redisClient, connectRedis } = require('./redis.js');
const { pool } = require('./config/database');

// Import middleware
const { corsMiddleware, preflightMiddleware } = require('./middleware/cors');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const messageRoutes = require('./routes/messages');
const statsRoutes = require('./routes/stats');
const formRoutes = require('./routes/form');

const app = express();
const port = process.env.PORT;

// Simple database initialization
const initializeDatabase = () => {
  console.log('🔌 Database connection pool created');
};

// Connect to Redis
console.log('🔌 Connecting to Redis...');
connectRedis();

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(corsMiddleware);

// Handle OPTIONS preflight for all routes
app.options('*', preflightMiddleware);

// Routes
app.use('/', authRoutes);
app.use('/', userRoutes);
app.use('/', messageRoutes);
app.use('/', statsRoutes);
app.use('/', formRoutes);

// Health check endpoint
app.get('/ping', (req, res) => {
  res.status(200).send({ success: true });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Server error:', err.message);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message:
      process.env.NODE_ENV === 'development'
        ? err.message
        : 'Something went wrong',
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.originalUrl,
  });
});

// Start server
app.listen(port, () => {
  console.log('🚀 Server started successfully!');
  console.log(`🌐 Server running on port: ${port}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('✨ Ready to handle requests');
});

// Initialize database
initializeDatabase();
