require("dotenv").config();
const { pool } = require("./db");

async function createTables() {
    try {
        // SQLite ya crea las tablas automáticamente en db.js
        // Este script es principalmente para Supabase
        // Si usas SQLite local, no necesitas ejecutar este script
        
        // Para Supabase (comentado cuando usas SQLite local):
        /*
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS texts (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES users(id),
                cipher TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        */

        console.log("✅ Tablas listas (SQLite las crea automáticamente)");
        console.log("💡 Si usas Supabase, descomenta el código en init.js");
        process.exit(0);
    } catch (err) {
        console.error("Error creando tablas:", err);
        process.exit(1);
    }
}

createTables();
