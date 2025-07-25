const { createClient } = require('redis');
require('dotenv').config();

const redisClient = createClient({
    url: process.env.REDIS_URL,
    socket: {
        tls: true,
        reconnectStrategy: retries => Math.min(retries * 50, 2000)
    }
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));

const connectRedis = async () => {
    if (!redisClient.isOpen) {
        try {
            await redisClient.connect();
            console.log("Connected to Redis");
        } catch (err) {
            console.error("Failed to connect to Redis:", err);
        }
    }
};

module.exports = { redisClient, connectRedis };
