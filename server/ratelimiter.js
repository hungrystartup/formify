const { RateLimiterRedis } = require('rate-limiter-flexible');
const { redisClient } = require('./redis');

let rateLimiter;

function createRateLimiter() {
    if (!redisClient.isReady) {
        throw new Error("Redis is not ready. Connect before initializing rate limiter.");
    }

    rateLimiter = new RateLimiterRedis({
        storeClient: redisClient,
        points: 100,
        duration: 3600,
        keyPrefix: 'rl'
    });

    return async function rateLimitMiddleware(req, res, next) {
        const apikey = req.headers['x-api-key'] || 'anonymous';
        try {
            await rateLimiter.consume(apikey);
            next();
        } catch (err) {
            res.status(429).send({ err: 'Too many requests', message: 'Rate limit exceeded, please try again later' });
        }
    };
}

module.exports = createRateLimiter;
