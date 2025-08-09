const { pool } = require('../config/database');

const getApiKey = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT api_key from users WHERE id = ? ',
      [req.user.id]
    );

    if (rows.length === 0)
      return res.status(400).send({
        success: false,
        error: 'user not found',
      });

    res.status(200).send({ success: true, message: rows[0].api_key });
  } catch (err) {
    console.log(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

const getUsername = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT username FROM users WHERE id = ? ',
      [req.user.id]
    );
    if (rows.length === 0)
      return res.status(400).send({
        success: false,
        error: 'user not found',
      });

    res.status(200).send({ success: true, message: rows[0].username });
  } catch (err) {
    console.log(err.message);
    res.status(200).send({ success: false, error: err.message });
  }
};

const getStatus = async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT status FROM users WHERE id = ? ',
      [req.user.id]
    );

    if (rows.length === 0)
      return res.status(400).send({
        success: false,
        error: 'User not found',
      });

    res.status(200).send({ success: true, stats: rows[0].status });
  } catch (err) {
    console.log(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

module.exports = {
  getApiKey,
  getUsername,
  getStatus,
};
