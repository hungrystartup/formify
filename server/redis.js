const { createClient } = require('redis');
require('dotenv').config();
const redisClient = createClient({
    url: process.env.REDIS_URL
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.connect();

module.exports = redisClient;
