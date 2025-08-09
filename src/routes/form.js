const express = require('express');
const router = express.Router();
const { submitForm } = require('../controllers/messageController');
const rateLimiter = require('../ratelimiter.js');

// Public route for form submission
router.post('/v1/submit/:apikey', rateLimiter, submitForm);

module.exports = router;
