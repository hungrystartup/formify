const { RateLimiterRedis } = require('rate-limiter-flexible');
const { redisClient } = require('./redis');

let rateLimiter;

if (redisClient.isReady) {
    rateLimiter = new RateLimiterRedis({
        storeClient: redisClient,
        points: 100,
        duration: 3600,
        keyPrefix: 'rl'
    });
    console.log("Rate limiter initialized.");
} else {
    console.warn("Redis is not ready. Rate limiter is disabled.");
}

const rateLimitMiddleware = async (req, res, next) => {
    const apikey = req.headers['x-api-key'] || 'anonymous';
    try {
        if (rateLimiter) {
            await rateLimiter.consume(apikey);
        }
        next();
    } catch (err) {
        res.status(429).send({ err: 'Too many requests', message: 'Rate limit exceeded, please try again later' });
    }
};

module.exports = rateLimitMiddleware;
