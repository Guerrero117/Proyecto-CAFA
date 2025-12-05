Problemas Detectados:
Clave de cifrado hardcodeadaen `js/crypto.js` (visible en el navegador)
JWT almacenado en localStorage (vulnerable a XSS)
Sin validación de contraseñas** (aceptaba cualquier contraseña)
Sin protección adicional** contra SQL injection (aunque usaba parámetros)
URLs inconsistentes** (algunas usaban ngrok, otras rutas relativas)
Sin refresh tokens (tokens de larga duración)

-CAMBIOS IMPLEMENTADOS
Protección contra SQL Injection
Archivo `server.js`

Cambios
-Función `sanitizeInput()` para limpiar entradas
Función `validateUsername()` con validación de formato
- Validación de tipos y rangos (user_id, longitudes máximas)
- Todas las consultas usan parámetros preparados (`$1`, `$2`)

Código agregado
```javascript
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().slice(0, 1000);
}

function validateUsername(username) {
    // Validación de longitud y formato
    if (!/^[a-zA-Z0-9_]+$/.test(sanitized)) {
        return { valid: false, msg: "El usuario solo puede contener letras, números y guiones bajos" };
    }
    // ...
}
```

Cifrado Movido al Servidor
- `server.js`: Nuevos endpoints `/encrypt` y `/decrypt`
- `js/crypto.js`: Deshabilitado (solo comentarios)
- `js/auth.js`: Actualizado para usar endpoints del servidor
- `encrypt.html`, `decrypt.html`: Actualizados

```javascript
// server.js - SEGURO
const CRYPTO_KEY = process.env.CRYPTO_KEY; // Solo en servidor

app.post("/encrypt", verifyToken, async (req, res) => {
    const cipher = CryptoJS.AES.encrypt(plainText, CRYPTO_KEY).toString();
    res.json({ ok: true, cipher });
});
```

Variables de Entorno para Claves Secretas
**Archivo:** `server.js`

**Variables agregadas:**
- `SECRET_KEY`: Para JWT access tokens (requerida)
- `REFRESH_SECRET_KEY`: Para refresh tokens (opcional)
- `CRYPTO_KEY`: Para cifrado AES (requerida)

**Validación:**
```javascript
if (!SECRET_KEY) {
    console.error("ERROR: SECRET_KEY no está definida en .env");
    process.exit(1);
}
```

Validación de Contraseñas
Archivo`server.js`

Validaciones implementadas

```javascript
function validatePassword(password) {
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
```
Refresh Tokens y Cookies HttpOnly
**Archivo:** `server.js`

- **Access tokens**: 15 minutos de duración, cookies httpOnly
-  **Refresh tokens**: 7 días de duración, cookies httpOnly
-  Renovación automática cuando el access token expira
-  Endpoint `/refresh-token` para renovación manual
-  Endpoint `/logout` que limpia las cookies
-  Cookies `secure: true` en producción (HTTPS)
-  Cookies `sameSite: 'strict'` (protección CSRF)

**Antes:**
```javascript
// VULNERABLE a XSS
localStorage.setItem("token", data.token);
```

**Ahora:**
```javascript
// SEGURO - Cookies httpOnly
res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
});
```

 Single-Tab Session
- `server.js`: Almacenamiento de sesiones activas
- `js/auth.js`: Detección de múltiples pestañas
- `encrypt.html`, `decrypt.html`: Verificación de sesión activa
flujo 
-  Solo una pestaña puede tener sesión activa por usuario
-  Si se pega la URL en otra pestaña, redirige al login
- Si se inicia sesión en otra pestaña, la anterior se cierra automáticamente
- Usa `BroadcastChannel` y `localStorage` para comunicación entre pestañas

**Implementación:**
```javascript
// Backend: Almacenar sesiones activas
const activeSessions = new Map(); // userId -> sessionId

// Al hacer login, generar sessionId único
const sessionId = crypto.randomBytes(32).toString('hex');
activeSessions.set(user.id, sessionId);

// Frontend: Detectar múltiples pestañas
const sessionChannel = new BroadcastChannel('cafa-session');
sessionChannel.onmessage = (event) => {
    if (event.data.type === 'new-login' && event.data.tabId !== sessionTabId) {
        handleSessionConflict(); // Cerrar esta pestaña
    }
};
```

---

cambios del front


**`js/auth.js` 
-  Eliminado uso de `localStorage` para tokens
-  Todas las peticiones con `credentials: "include"` (para cookies)
-  Nuevas funciones: `verifyAuth()`, `logout()`, `encryptText()`, `decryptText()`
-  Sistema de detección de múltiples pestañas
-  Funciones para single-tab session

**`js/crypto.js` - Deshabilitado:**
-  Cifrado ahora se hace en el servidor
-  Solo contiene comentarios informativos

**`index.html`, `register.html`:**
- ✅ Actualizados para usar nuevas funciones de autenticación

**`encrypt.html`, `decrypt.html`:**
-  Usan endpoints `/encrypt` y `/decrypt` del servidor
-  Verificación de sesión activa al cargar
-  Redirección automática si no tienen sesión activa

---

endpoins Agregados en `server.js`:

1. **`POST /encrypt`** - Cifrar texto en el servidor
   - Requiere autenticación
   - Recibe: `{ plainText }`
   - Retorna: `{ ok: true, cipher }`

2. **`POST /decrypt`** - Descifrar texto en el servidor
   - Requiere autenticación
   - Recibe: `{ cipher }`
   - Retorna: `{ ok: true, plainText }`

3. **`POST /refresh-token`** - Renovar access token
   - Usa refresh token de cookie
   - Retorna nuevo access token

4. **`POST /logout`** - Cerrar sesión
   - Limpia todas las cookies
   - Elimina sesión activa del servidor

5. **`GET /verify-auth`** - Verificar autenticación
   - Retorna estado de autenticación
   - Usado por frontend para verificar sesión

---

#### Dependencias Agregadas:
- `cookie-parser`: Para manejar cookies

FLUJO DE AUTENTICACIÓN ACTUAL

### 1. Registro:
```
Usuario → Frontend → POST /register
  → Validación de username y contraseña
  → Hash de contraseña (bcrypt)
  → Guardar en BD
  → Respuesta OK
```

### 2. Login:
```
Usuario → Frontend → POST /login
  → Validación de credenciales
  → Generar sessionId único
  → Generar access token (15 min)
  → Generar refresh token (7 días)
  → Guardar en cookies httpOnly
  → Invalidar sesión anterior si existe
  → Notificar otras pestañas
  → Respuesta OK
```

### 3. Uso de la Aplicación:
```
Usuario → Frontend → Petición con cookies
  → Servidor verifica cookies
  → Verifica sessionId en activeSessions
  → Si expira access token, renueva automáticamente
  → Procesa petición
```

### 4. Cifrado/Descifrado:
```
Usuario → Frontend → POST /encrypt o /decrypt
  → Servidor verifica autenticación
  → Cifra/descifra en servidor con CRYPTO_KEY
  → Retorna resultado
```

### 5. Single-Tab Session:
```
Pestaña 1: Inicia sesión → sessionId guardado
Pestaña 2: Intenta acceder → No tiene sessionId → Redirige a login
Pestaña 2: Inicia sesión → Nueva sessionId → Pestaña 1 detecta → Se cierra
```


 NOTAS 

1. **Migración de Usuarios:**
   - Los usuarios existentes seguirán funcionando
   - Necesitarán iniciar sesión nuevamente (nuevo sistema de tokens)

2. **Textos Cifrados Antiguos:**
   - Siguen siendo descifrables si usas la misma `CRYPTO_KEY`
   - Si cambias `CRYPTO_KEY`, los textos antiguos no se podrán descifrar

3. **Single-Tab Session:**
   - Si un usuario cierra la pestaña, la sesión sigue activa en el servidor
   - Al abrir nueva pestaña, necesitará iniciar sesión nuevamente

4. **Cookies:**
   - En desarrollo: funcionan en HTTP
   - En producción: requieren HTTPS (configurado automáticamente)

---
