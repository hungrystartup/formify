const sanitizeHtml = require('sanitize-html');
const { pool } = require('../config/database');

const submitForm = async (req, res) => {
  const referrer = req.get('referer');
  const safeReferrer = (referrer || '').substring(0, 255);
  const { apikey } = req.params;
  const { email, message, _redirect } = req.body;

  if (!email || !message) {
    return res.status(400).json({
      success: false,
      error: 'Message content or email is required',
    });
  }

  // Sanitize input
  const cleanEmail = sanitizeHtml(email.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  const cleanMessage = sanitizeHtml(message.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  // Basic email format validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid email format',
    });
  }

  try {
    const [[user]] = await pool.execute(
      'SELECT id, email, max_message, current_message, status FROM users WHERE api_key = ?',
      [apikey]
    );

    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.current_message >= user.max_message) {
      return res.redirect(`${process.env.FRONTEND_URL}/limitreached.html`);
    }

    await pool.execute(
      'INSERT INTO messages (user_id, content, submitted_email, site_url) VALUES (?, ?, ?, ?)',
      [user.id, cleanMessage, cleanEmail, safeReferrer]
    );

    await pool.execute(
      'UPDATE users SET current_message = current_message + 1, total_messages = total_messages + 1 WHERE id = ?',
      [user.id]
    );

    // Redirect logic
    if (user.status === 0) {
      return res.redirect(`${process.env.FRONTEND_URL}/thanks.html`);
    }

    if (user.status === 1 && _redirect) {
      return res.redirect(_redirect);
    }

    return res.status(200).json({
      success: true,
      message: 'Message received',
    });
  } catch (err) {
    console.error('MySQL Submit error:', err); // full error object
    res.status(500).json({
      error: 'Server error',
      details: err.sqlMessage || err.message,
    });
  }
};

const getMessages = async (req, res) => {
  const limit = 5;

  try {
    const sql = `
            SELECT id, submitted_email, content, received_at, site_url
            FROM messages
            WHERE user_id = ?
            ORDER BY received_at DESC
            LIMIT ${limit}
        `;

    const [messages] = await pool.query(sql, [req.user.id]);

    res.status(200).json({ success: true, messages });
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

const getPaginatedMessages = async (req, res) => {
  const limit = parseInt(req.query.limit) || 4;
  const offset = parseInt(req.query.offset) || 0;

  try {
    const sql = `
            SELECT id, content, received_at, site_url
            FROM messages
            WHERE user_id = ?
            ORDER BY received_at DESC
            LIMIT ${limit} OFFSET ${offset}
        `;

    const [messages] = await pool.query(sql, [req.user.id]);

    res.status(200).send({ success: true, messages });
  } catch (err) {
    console.log(err.message);
    res.status(400).send({ success: false, error: err.message });
  }
};

const deleteMessage = async (req, res) => {
  const id = req.query.id;
  try {
    const [[user]] = await pool.execute(
      'SELECT status FROM users WHERE id = ? ',
      [req.user.id]
    );
    if (user.length == 0)
      return res.status(400).send({
        success: false,
        error: 'User does not exist',
      });

    if (user.status == 0)
      return res.status(401).send({
        success: false,
        error: 'Only premium users can delete messages',
      });

    await pool.execute('DELETE FROM messages WHERE id = ?', [id]);
    await pool.execute(
      'UPDATE users SET current_message = current_message - 1, total_messages = total_messages - 1 WHERE id = ?',
      [req.user.id]
    );
    res.status(200).send({
      success: true,
      message: 'Message successfully deleted',
    });
  } catch (err) {
    console.log(err.message);
  }
};

module.exports = {
  submitForm,
  getMessages,
  getPaginatedMessages,
  deleteMessage,
};
