const { redisClient, connectRedis } = require('./redis.js');

module.exports = async function rateLimiter(req, res, next) {
  const apiKey = req.headers['x-api-key'] || 'anonymous';
  const key = `rate-limit:${apiKey}`;
  const limit = 100;
  const windowInSeconds = 3600;

  try {
    await connectRedis(); // 👈 Ensure Redis is connected before using

    let current = await redisClient.get(key);

    if (current !== null && parseInt(current) >= limit) {
      return res
        .status(429)
        .send({ error: 'Rate limit exceeded. Try again later' });
    }

    const pipeline = redisClient.multi();
    pipeline.incr(key);

    if (current === null) {
      pipeline.expire(key, windowInSeconds);
    }

    await pipeline.exec();
    next();
  } catch (err) {
    console.error('Rate limiter error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
