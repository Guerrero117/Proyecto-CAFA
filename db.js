require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
    user: process.env.DB_USER,        // postgres
    password: process.env.DB_PASSWORD, // tu contraseña
    host: process.env.DB_HOST,        // db.rhscaieuhyzlsgnwvxll.supabase.co
    port: process.env.DB_PORT,        // 5432
    database: process.env.DB_NAME,    // proyecto
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on("connect", () => {
    console.log("Conexión exitosa a Supabase PostgreSQL");
});

module.exports = { pool };
