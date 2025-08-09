const cors = require('cors');

const corsOptions = {
  origin: true, // Allow all origins
  credentials: true, // Must be true for cookies
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

const corsMiddleware = cors(corsOptions);

// Handle OPTIONS preflight for all routes
const preflightMiddleware = cors({
  origin: true,
  credentials: true,
});

module.exports = { corsMiddleware, preflightMiddleware };
