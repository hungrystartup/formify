const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  user: process.env.DATABASE_USER,
  database: process.env.DATABASE_NAME,
  host: process.env.DATABASE_HOST,
  password: process.env.DATABASE_PASSWORD,
  waitForConnections: true,
  connectionLimit: 30,
  queueLimit: 0,
});

// Database connection logging
pool.on('connection', () => {
  console.log('✅ Database connected');
});

pool.on('error', (error) => {
  console.error('❌ Database error:', error.message);
});

module.exports = { pool };
