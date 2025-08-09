const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('../config/database');

const signup = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    if (!name || !email || !password) {
      return res.status(400).send({
        success: false,
        error: 'Fields cannot be empty',
      });
    }

    const [rows] = await pool.execute('SELECT id FROM users WHERE email = ?', [
      email,
    ]);
    if (rows.length > 0) {
      return res.status(409).send({
        success: false,
        error: 'Email has already been used',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const apiKey = crypto.randomBytes(32).toString('hex');

    const [result] = await pool.execute(
      'INSERT INTO users(username, email, password, api_key) VALUES(?, ?, ?, ?)',
      [name, email, hashedPassword, apiKey]
    );

    const userId = result.insertId;

    const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.cookie('token', token, {
      httpOnly: true, // Prevent JavaScript access
      secure: true, // Required for HTTPS and SameSite=None
      sameSite: 'None', // Allow cross-subdomain requests
      domain: '.bluhorizon.work',
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
    });

    res.status(200).send({ success: true, message: 'Sign up successful' });
  } catch (err) {
    console.error(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).send({
        success: false,
        error: 'Fields cannot be empty',
      });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [
      email,
    ]);
    const user = rows[0];

    const isMatch = user && (await bcrypt.compare(password, user.password));
    if (!isMatch) {
      return res.status(409).send({
        success: false,
        error: 'Invalid credentials',
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.cookie('token', token, {
      httpOnly: true, // Prevent JavaScript access
      secure: true, // Required for HTTPS and SameSite=None
      sameSite: 'None', // Allow cross-subdomain requests
      domain: '.bluhorizon.work',
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
    });
    console.log('Set-Cookie: token=', token);
    res.status(200).send({ success: true });
  } catch (err) {
    console.error(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

const logout = (req, res) => {
  try {
    res.clearCookie('token', {
      httpOnly: true, // Prevent JavaScript access
      secure: true, // Required for HTTPS and SameSite=None
      domain: '.bluhorizon.work',
      sameSite: 'None', // Allow cross-subdomain requests
    });
    res.status(200).send({ success: true });
  } catch (err) {
    console.log(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

const authorize = (req, res) => {
  res.send({ success: true });
};

module.exports = {
  signup,
  login,
  logout,
  authorize,
};
