require("dotenv").config();

// ===== MODO LOCAL (SQLite) - Para pruebas sin Supabase =====
// Para usar SQLite local, descomenta la sección LOCAL y comenta la sección SUPABASE
// Para volver a Supabase, invierte los comentarios

// ===== LOCAL: SQLite (Para pruebas) =====
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, 'local.db');

// Crear conexión SQLite
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error conectando a SQLite:', err);
    } else {
        console.log('✅ Conectado a SQLite local (local.db)');
        // Crear tablas si no existen
        db.serialize(() => {
            db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            `);
            db.run(`
                CREATE TABLE IF NOT EXISTS texts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    cipher TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);
        });
    }
});

// Wrapper para hacer SQLite compatible con pg (pool.query)
const pool = {
    query: (text, params) => {
        return new Promise((resolve, reject) => {
            // Convertir parámetros $1, $2 a ? para SQLite
            let sql = text;
            if (params && params.length > 0) {
                sql = text.replace(/\$(\d+)/g, (match, index) => {
                    return '?';
                });
            }
            
            if (text.trim().toUpperCase().startsWith('SELECT')) {
                db.all(sql, params || [], (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ rows: rows || [] });
                    }
                });
            } else {
                db.run(sql, params || [], function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ rows: [], rowCount: this.changes });
                    }
                });
            }
        });
    }
};

// ===== SUPABASE: PostgreSQL (Producción) - COMENTADO PARA PRUEBAS LOCALES =====
/*
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
*/

module.exports = { pool };
