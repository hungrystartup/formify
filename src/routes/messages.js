const express = require('express');
const router = express.Router();
const {
  getMessages,
  getPaginatedMessages,
  deleteMessage,
} = require('../controllers/messageController');
const { verifyToken } = require('../middleware/auth');

// All message routes are protected
router.use(verifyToken);

router.get('/api/messages', getMessages);
router.get('/api/message', getPaginatedMessages);
router.get('/delete', deleteMessage);

module.exports = router;
