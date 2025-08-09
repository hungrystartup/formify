const express = require('express');
const router = express.Router();
const {
  getTotalMessages,
  getCurrentMessages,
  getMessageLimit,
  getMessageProgress,
  getMessageStats,
} = require('../controllers/statsController');
const { verifyToken } = require('../middleware/auth');

// All stats routes are protected
router.use(verifyToken);

router.get('/api/total', getTotalMessages);
router.get('/api/current', getCurrentMessages);
router.get('/api/limit', getMessageLimit);
router.get('/message-progress', getMessageProgress);
router.get('/api/message-stats', getMessageStats);

module.exports = router;
