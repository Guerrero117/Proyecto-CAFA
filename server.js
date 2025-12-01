require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { pool } = require("./db");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 3000;

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));

// Limitar intentos de login
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5,
    message: "Demasiados intentos, intenta de nuevo en 1 minuto"
});
app.use("/login", limiter);

// ===== REGISTRO =====
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ ok: false, msg: "Datos inválidos" });

    try {
        const exists = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
        if (exists.rows.length > 0) return res.json({ ok: false, msg: "Usuario ya existe" });

        const hashed = bcrypt.hashSync(password, 10);
        await pool.query("INSERT INTO users (username, password_hash) VALUES ($1,$2)", [username, hashed]);
        res.json({ ok: true, msg: "Usuario registrado correctamente" });
    } catch (err) {
        console.log(err);
        res.json({ ok: false, msg: "Error al registrar usuario" });
    }
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
        if (result.rows.length === 0) return res.json({ ok: false, msg: "Usuario no encontrado" });

        const user = result.rows[0];
        const valid = bcrypt.compareSync(password, user.password_hash);
        if (!valid) return res.json({ ok: false, msg: "Contraseña incorrecta" });

        const token = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY, { expiresIn: "2h" });
        res.json({ ok: true, msg: "Login correcto", token, userId: user.id });
    } catch (err) {
        console.log(err);
        res.json({ ok: false, msg: "Error al iniciar sesión" });
    }
});

// ===== MIDDLEWARE DE TOKEN =====
function verifyToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).json({ msg: "Token requerido" });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ msg: "Token inválido" });
    }
}

// ===== GUARDAR TEXTO CIFRADO =====
app.post("/save-text", verifyToken, async (req, res) => {
    const { cipher } = req.body;
    if (!cipher) return res.json({ ok: false, msg: "No se recibió texto cifrado" });

    try {
        await pool.query(
            "INSERT INTO texts (user_id, cipher) VALUES ($1, $2)",
            [req.user.id, cipher]
        );
        res.json({ ok: true, msg: "Texto guardado" });
    } catch (err) {
        console.error(err);
        res.json({ ok: false, msg: "Error al guardar texto" });
    }
});

// ===== OBTENER TEXTOS CIFRADOS =====
app.get("/my-texts", verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM texts WHERE user_id=$1 ORDER BY created_at DESC",
            [req.user.id]
        );
        res.json({ ok: true, rows: result.rows });
    } catch (err) {
        console.error(err);
        res.json({ ok: false, msg: "Error al obtener textos" });
    }
});

// Servir index.html en la raíz
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
