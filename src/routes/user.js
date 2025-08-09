const express = require('express');
const router = express.Router();
const {
  getApiKey,
  getUsername,
  getStatus,
} = require('../controllers/userController');
const { verifyToken } = require('../middleware/auth');

// All user routes are protected
router.use(verifyToken);

router.get('/apikey', getApiKey);
router.get('/username', getUsername);
router.get('/api/status', getStatus);

module.exports = router;
