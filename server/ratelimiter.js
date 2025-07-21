// Adding redis rate limiter.
const { RateLimiterRedis } = require('rate-limiter-flexible');
const redisClient = require('./redis');
//Rate Limiter configuration
const rateLimiter = new RateLimiterRedis({
    storeClient: redisClient,
    points: 100, //Allowing 2 requests
    duration: 3600, //Per hour 
    keyPrefix: 'rl' //Prefix for redis keys
});
// MiddleWare to apply rate limiting based on Api key
const rateLimitMiddleware = async (req, res, next) => {
    const apikey = req.headers['x-api-key'] || 'anonymous'; //Fallbackto anonymous if no api key
    try{
        await rateLimiter.consume(apikey);
        next();
    }catch(err){
        res.status(429).send({err: 'Too many requests', message: 'Rate limit exceeded, please try again later'});
    }
};
module.exports = rateLimitMiddleware;
