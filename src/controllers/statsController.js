const { pool } = require('../config/database');

const getTotalMessages = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT total_messages FROM users WHERE id = ?',
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ total: rows[0].total_messages });
  } catch (err) {
    console.error('total fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

const getCurrentMessages = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT current_message FROM users WHERE id = ?',
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ current: rows[0].current_message });
  } catch (err) {
    console.error('current fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

const getMessageLimit = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT max_message FROM users WHERE id = ?',
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ limit: rows[0].max_message });
  } catch (err) {
    console.error('Limit fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

const getMessageProgress = async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await pool.execute(
      'SELECT current_message, max_message FROM users WHERE id = ?',
      [userId]
    );

    if (rows.length === 0)
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });

    const { current_message, max_message } = rows[0];
    res.status(200).json({ success: true, current_message, max_message });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: err.message });
  }
};

const getMessageStats = async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await pool.query(
      `
           SELECT 
            SUM(CASE WHEN DATE(received_at) = CURDATE() THEN 1 ELSE 0 END) AS today,
            SUM(CASE WHEN YEARWEEK(received_at, 1) = YEARWEEK(CURDATE(), 1) THEN 1 ELSE 0 END) AS this_week,
            SUM(CASE WHEN MONTH(received_at) = MONTH(CURDATE()) AND YEAR(received_at) = YEAR(CURDATE()) THEN 1 ELSE 0 END) AS this_month,
            SUM(CASE WHEN YEAR(received_at) = YEAR(CURDATE()) THEN 1 ELSE 0 END) AS this_year
            FROM messages
            WHERE user_id = ?
            `,
      [userId]
    );

    res.json({ success: true, ...rows[0] });
  } catch (err) {
    console.error('Stats fetch error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
};

module.exports = {
  getTotalMessages,
  getCurrentMessages,
  getMessageLimit,
  getMessageProgress,
  getMessageStats,
};
