const mysql = require('mysql2');
require('dotenv').config();

const conn = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME
});

conn.connect(err => {
    if(err) throw err;
    console.log("Connected to database");
});

module.export = conn;
