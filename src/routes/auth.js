const express = require('express');
const router = express.Router();
const {
  signup,
  login,
  logout,
  authorize,
} = require('../controllers/authController');
const { verifyToken } = require('../middleware/auth');
const rateLimiter = require('../ratelimiter.js');

// Public routes
router.post('/signup', rateLimiter, signup);
router.post('/login', rateLimiter, login);
router.post('/logout', rateLimiter, logout);

// Protected routes
router.get('/authorize', verifyToken, authorize);

module.exports = router;
