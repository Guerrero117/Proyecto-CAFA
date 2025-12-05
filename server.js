require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const CryptoJS = require("crypto-js");
const { pool } = require("./db");
const path = require("path");

const app = express();

// ===== ALMACENAMIENTO DE SESIONES ACTIVAS (Single-tab Session) =====
// Almacena userId -> sessionId para permitir solo una sesión por usuario
const activeSessions = new Map();

// Configuración CORS para cookies
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Variables de entorno
const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY || SECRET_KEY + "_refresh";
const CRYPTO_KEY = process.env.CRYPTO_KEY;
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

// Validación de que existan las claves necesarias en el .env
if (!SECRET_KEY) {
    console.error("ERROR: SECRET_KEY no está definida en .env");
    process.exit(1);
}
if (!CRYPTO_KEY) {
    console.error("ERROR: CRYPTO_KEY no está definida en .env");
    process.exit(1);
}

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));

// Limitar intentos de login y registro
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5,
    message: "Demasiados intentos, intenta de nuevo en 1 minuto"
});
app.use("/login", limiter);
app.use("/register", limiter);

// ===== VALIDACIÓN DE CONTRASEÑA =====
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, msg: "La contraseña es requerida" };
    }
    if (password.length < 8) {
        return { valid: false, msg: "La contraseña debe tener al menos 8 caracteres" };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, msg: "La contraseña debe contener al menos una mayúscula" };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, msg: "La contraseña debe contener al menos un número" };
    }
    return { valid: true };
}

// Protección SQL Injection) 
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    // Eliminar caracteres peligrosos y limitar longitud
    return input.trim().slice(0, 1000);
}

function validateUsername(username) {
    if (!username || typeof username !== 'string') {
        return { valid: false, msg: "El usuario es requerido" };
    }
    const sanitized = sanitizeInput(username);
    if (sanitized.length < 3 || sanitized.length > 50) {
        return { valid: false, msg: "El usuario debe tener entre 3 y 50 caracteres" };
    }
    if (!/^[a-zA-Z0-9_]+$/.test(sanitized)) {
        return { valid: false, msg: "El usuario solo puede contener letras, números y guiones bajos" };
    }
    return { valid: true, sanitized };
}

// ===== REGISTRO =====
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    
    // Validar username
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
        return res.json({ ok: false, msg: usernameValidation.msg });
    }
    const sanitizedUsername = usernameValidation.sanitized;

    // Validar contraseña
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        return res.json({ ok: false, msg: passwordValidation.msg });
    }

    try {
        // Verificar si el usuario existe
        const exists = await pool.query("SELECT * FROM users WHERE username=$1", [sanitizedUsername]);
        if (exists.rows.length > 0) {
            return res.json({ ok: false, msg: "Usuario ya existe" });
        }

        // Hash de contraseña
        const hashed = bcrypt.hashSync(password, 10);
        
        // Insertar usuario 
        await pool.query("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [sanitizedUsername, hashed]);
        
        res.json({ ok: true, msg: "Usuario registrado correctamente" });
    } catch (err) {
        console.error("Error al registrar usuario:", err);
        res.json({ ok: false, msg: "Error al registrar usuario" });
    }
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    
    // Validar entrada
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
        return res.json({ ok: false, msg: usernameValidation.msg });
    }
    const sanitizedUsername = usernameValidation.sanitized;

    if (!password || typeof password !== 'string') {
        return res.json({ ok: false, msg: "Contraseña requerida" });
    }

    try {
        // Buscar usuario (protección SQL injection con parámetros)
        const result = await pool.query("SELECT * FROM users WHERE username=$1", [sanitizedUsername]);
        if (result.rows.length === 0) {
            return res.json({ ok: false, msg: "Usuario no encontrado" });
        }

        const user = result.rows[0];
        const valid = bcrypt.compareSync(password, user.password_hash);
        if (!valid) {
            return res.json({ ok: false, msg: "Contraseña incorrecta" });
        }

        // ===== SINGLE-TAB SESSION: Generar sessionId único =====
        const crypto = require('crypto');
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        // Invalidar sesión anterior si existe (solo una sesión activa por usuario)
        if (activeSessions.has(user.id)) {
            const oldSessionId = activeSessions.get(user.id);
            console.log(`Sesión anterior invalidada para usuario ${user.id}: ${oldSessionId}`);
        }
        
        // Guardar nueva sesión activa
        activeSessions.set(user.id, sessionId);

        // Generar access token (corta duración) con sessionId
        const accessToken = jwt.sign(
            { username: user.username, id: user.id, type: 'access', sessionId },
            SECRET_KEY,
            { expiresIn: "15m" }
        );

        // Generar refresh token (larga duración) con sessionId
        const refreshToken = jwt.sign(
            { username: user.username, id: user.id, type: 'refresh', sessionId },
            REFRESH_SECRET_KEY,
            { expiresIn: "7d" }
        );

        // Guardar refresh token en cookie httpOnly
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: NODE_ENV === 'production', // Solo HTTPS en producción
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 días
        });

        // Enviar access token en cookie también (para mayor seguridad)
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutos
        });

        // Guardar sessionId en cookie para verificación
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutos
        });

        res.json({ ok: true, msg: "Login correcto", userId: user.id, sessionId });
    } catch (err) {
        console.error("Error al iniciar sesión:", err);
        res.json({ ok: false, msg: "Error al iniciar sesión" });
    }
});

// ===== MIDDLEWARE DE TOKEN =====
function verifyToken(req, res, next) {
    // Intentar obtener token de cookie primero, luego de header
    let token = req.cookies.accessToken || req.headers["authorization"];
    
    if (!token) {
        return res.status(403).json({ ok: false, msg: "Token requerido" });
    }

    // Si viene del header, puede tener formato "Bearer token"
    if (token.startsWith('Bearer ')) {
        token = token.slice(7);
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        
        // Verificar que sea un access token
        if (decoded.type !== 'access') {
            return res.status(401).json({ ok: false, msg: "Token inválido" });
        }
        
        // ===== SINGLE-TAB SESSION: Verificar que la sesión sea válida =====
        const sessionId = req.cookies.sessionId;
        const storedSessionId = activeSessions.get(decoded.id);
        
        if (!sessionId || !storedSessionId || sessionId !== storedSessionId) {
            // Sesión inválida (otra pestaña inició sesión o sesión expirada)
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            res.clearCookie('sessionId');
            return res.status(401).json({ ok: false, msg: "Sesión inválida. Por favor, inicia sesión nuevamente." });
        }
        
        // Verificar que el sessionId del token coincida
        if (decoded.sessionId !== sessionId) {
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            res.clearCookie('sessionId');
            return res.status(401).json({ ok: false, msg: "Sesión inválida. Por favor, inicia sesión nuevamente." });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        // Si el token expiró, intentar refrescar
        if (err.name === 'TokenExpiredError') {
            return refreshAccessToken(req, res, next);
        }
        res.status(401).json({ ok: false, msg: "Token inválido" });
    }
}

// ===== REFRESH TOKEN =====
async function refreshAccessToken(req, res, next) {
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
        return res.status(401).json({ ok: false, msg: "Sesión expirada, por favor inicia sesión nuevamente" });
    }

    try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET_KEY);
        
        if (decoded.type !== 'refresh') {
            return res.status(401).json({ ok: false, msg: "Token inválido" });
        }

        // Verificar que el usuario aún existe
        const result = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
        if (result.rows.length === 0) {
            return res.status(401).json({ ok: false, msg: "Usuario no encontrado" });
        }

        const user = result.rows[0];

        // ===== SINGLE-TAB SESSION: Verificar que la sesión siga siendo válida =====
        const sessionId = req.cookies.sessionId;
        const storedSessionId = activeSessions.get(user.id);
        
        if (!sessionId || !storedSessionId || sessionId !== storedSessionId) {
            // Sesión inválida
            activeSessions.delete(user.id);
            res.clearCookie('refreshToken');
            res.clearCookie('accessToken');
            res.clearCookie('sessionId');
            return res.status(401).json({ ok: false, msg: "Sesión inválida. Por favor, inicia sesión nuevamente." });
        }

        // Generar nuevo access token con el mismo sessionId
        const newAccessToken = jwt.sign(
            { username: user.username, id: user.id, type: 'access', sessionId },
            SECRET_KEY,
            { expiresIn: "15m" }
        );

        // Actualizar cookie
        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000
        });

        req.user = { username: user.username, id: user.id };
        next();
    } catch (err) {
        // Refresh token inválido o expirado
        res.clearCookie('refreshToken');
        res.clearCookie('accessToken');
        res.status(401).json({ ok: false, msg: "Sesión expirada, por favor inicia sesión nuevamente" });
    }
}

// ===== ENDPOINT PARA REFRESCAR TOKEN =====
app.post("/refresh-token", async (req, res) => {
    await refreshAccessToken(req, res, () => {
        res.json({ ok: true, msg: "Token refrescado" });
    });
});

// ===== LOGOUT =====
app.post("/logout", verifyToken, (req, res) => {
    // Eliminar sesión activa
    if (req.user && req.user.id) {
        activeSessions.delete(req.user.id);
    }
    
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('sessionId');
    res.json({ ok: true, msg: "Sesión cerrada" });
});

// ===== CIFRAR TEXTO =====
app.post("/encrypt", verifyToken, async (req, res) => {
    const { plainText } = req.body;
    
    if (!plainText || typeof plainText !== 'string') {
        return res.json({ ok: false, msg: "Texto requerido" });
    }

    // Limitar longitud del texto
    const sanitizedText = plainText.trim().slice(0, 10000);
    
    if (!sanitizedText) {
        return res.json({ ok: false, msg: "El texto no puede estar vacío" });
    }

    try {
        // Cifrar en el servidor con la clave secreta
        const cipher = CryptoJS.AES.encrypt(sanitizedText, CRYPTO_KEY).toString();
        res.json({ ok: true, cipher });
    } catch (err) {
        console.error("Error al cifrar:", err);
        res.json({ ok: false, msg: "Error al cifrar texto" });
    }
});

// ===== DESCIFRAR TEXTO =====
app.post("/decrypt", verifyToken, async (req, res) => {
    const { cipher } = req.body;
    
    if (!cipher || typeof cipher !== 'string') {
        return res.json({ ok: false, msg: "Texto cifrado requerido" });
    }

    try {
        // Descifrar en el servidor
        const bytes = CryptoJS.AES.decrypt(cipher.trim(), CRYPTO_KEY);
        const plainText = bytes.toString(CryptoJS.enc.Utf8);
        
        if (!plainText) {
            return res.json({ ok: false, msg: "Texto cifrado inválido o clave incorrecta" });
        }
        
        res.json({ ok: true, plainText });
    } catch (err) {
        console.error("Error al descifrar:", err);
        res.json({ ok: false, msg: "Error al descifrar texto" });
    }
});

// ===== GUARDAR TEXTO CIFRADO =====
app.post("/save-text", verifyToken, async (req, res) => {
    const { cipher } = req.body;
    
    if (!cipher || typeof cipher !== 'string') {
        return res.json({ ok: false, msg: "No se recibió texto cifrado" });
    }

    // Sanitizar entrada (protección SQL injection)
    const sanitizedCipher = sanitizeInput(cipher).slice(0, 5000);

    try {
        // Guardar texto cifrado (protección SQL injection con parámetros)
        await pool.query(
            "INSERT INTO texts (user_id, cipher) VALUES ($1, $2)",
            [req.user.id, sanitizedCipher]
        );
        res.json({ ok: true, msg: "Texto guardado" });
    } catch (err) {
        console.error("Error al guardar texto:", err);
        res.json({ ok: false, msg: "Error al guardar texto" });
    }
});

// ===== OBTENER TEXTOS CIFRADOS =====
app.get("/my-texts", verifyToken, async (req, res) => {
    try {
        // Protección SQL injection: usar parámetros y validar user_id
        const userId = parseInt(req.user.id);
        if (isNaN(userId) || userId <= 0) {
            return res.json({ ok: false, msg: "ID de usuario inválido" });
        }

        const result = await pool.query(
            "SELECT id, cipher, created_at FROM texts WHERE user_id=$1 ORDER BY created_at DESC",
            [userId]
        );
        res.json({ ok: true, rows: result.rows });
    } catch (err) {
        console.error("Error al obtener textos:", err);
        res.json({ ok: false, msg: "Error al obtener textos" });
    }
});

// ===== VERIFICAR AUTENTICACIÓN =====
app.get("/verify-auth", verifyToken, (req, res) => {
    res.json({ ok: true, user: { id: req.user.id, username: req.user.username } });
});

// Servir index.html en la raíz
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
