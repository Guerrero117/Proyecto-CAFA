// Usar rutas relativas (mismo dominio)
const API_URL = "";

// ===== SINGLE-TAB SESSION: Detección de múltiples pestañas =====
let sessionChannel = null;
let sessionTabId = null;
let isSessionActive = false;
let conflictCheckInterval = null;

// Inicializar detección de múltiples pestañas (solo una vez)
function initSingleTabSession() {
    if (sessionTabId) return; // Ya inicializado
    
    // Generar ID único para esta pestaña
    sessionTabId = 'tab_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    // Usar BroadcastChannel para comunicación entre pestañas
    try {
        sessionChannel = new BroadcastChannel('cafa-session');
        
        // Escuchar mensajes de otras pestañas
        sessionChannel.onmessage = (event) => {
            if (event.data.type === 'new-login' && isSessionActive && event.data.tabId !== sessionTabId) {
                // Otra pestaña inició sesión y esta pestaña tiene sesión activa
                handleSessionConflict();
            }
        };
    } catch (err) {
        console.warn('BroadcastChannel no disponible:', err);
    }
    
    // Usar localStorage para detectar cambios (solo si esta pestaña tiene sesión activa)
    window.addEventListener('storage', (e) => {
        if (e.key === 'cafa-session-active' && isSessionActive && e.newValue && e.newValue !== sessionTabId) {
            // Otra pestaña tiene sesión activa y esta también
            handleSessionConflict();
        }
    });
}

// Manejar conflicto de sesión (otra pestaña inició sesión)
function handleSessionConflict() {
    // Evitar múltiples ejecuciones
    if (!isSessionActive) return;
    
    isSessionActive = false;
    
    // Limpiar intervalos
    if (conflictCheckInterval) {
        clearInterval(conflictCheckInterval);
        conflictCheckInterval = null;
    }
    
    // Limpiar localStorage
    localStorage.removeItem('cafa-session-active');
    
    // Notificar al usuario
    alert('Sesión iniciada en otra pestaña. Esta sesión se cerrará.');
    
    // Cerrar sesión y redirigir
    logout();
}

// Notificar a otras pestañas que se inició sesión
function notifyNewLogin() {
    if (!sessionTabId) {
        initSingleTabSession();
    }
    
    isSessionActive = true;
    
    if (sessionChannel) {
        sessionChannel.postMessage({ type: 'new-login', tabId: sessionTabId });
    }
    localStorage.setItem('cafa-session-active', sessionTabId);
    
    // Iniciar verificación periódica solo si hay sesión activa
    if (conflictCheckInterval) {
        clearInterval(conflictCheckInterval);
    }
    
    conflictCheckInterval = setInterval(() => {
        if (!isSessionActive) {
            clearInterval(conflictCheckInterval);
            return;
        }
        
        const activeTab = localStorage.getItem('cafa-session-active');
        if (activeTab && activeTab !== sessionTabId) {
            handleSessionConflict();
        }
    }, 3000); // Verificar cada 3 segundos
}

// Limpiar al cerrar sesión
function clearSessionTracking() {
    isSessionActive = false;
    
    if (conflictCheckInterval) {
        clearInterval(conflictCheckInterval);
        conflictCheckInterval = null;
    }
    
    if (sessionChannel) {
        sessionChannel.close();
        sessionChannel = null;
    }
    localStorage.removeItem('cafa-session-active');
    sessionTabId = null;
}

// Inicializar al cargar (solo estructura, no marca como activa)
if (typeof window !== 'undefined') {
    initSingleTabSession();
}

// ----- VERIFICAR AUTENTICACIÓN -----
async function verifyAuth() {
    try {
        const response = await fetch(API_URL + "/verify-auth", {
            method: "GET",
            credentials: "include" // Incluir cookies
        });
        const data = await response.json();
        
        if (data.ok) {
            // Si la autenticación es exitosa, marcar esta pestaña como activa
            if (!isSessionActive) {
                notifyNewLogin();
            }
            return true;
        } else {
            // Si la autenticación falla, limpiar tracking
            clearSessionTracking();
            return false;
        }
    } catch (err) {
        clearSessionTracking();
        return false;
    }
}

// ----- REGISTRO -----
async function registerUser(username, password) {
    try {
        const response = await fetch(API_URL + "/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        alert(data.msg);

        if (data.ok) {
            window.location.href = "index.html";
        }
    } catch (err) {
        alert("Error de conexión");
    }
}

// ----- LOGIN -----
async function loginUser(username, password) {
    try {
        const response = await fetch(API_URL + "/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include", // Incluir cookies
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.ok) {
            // ===== SINGLE-TAB SESSION: Notificar a otras pestañas =====
            notifyNewLogin();
            return true;
        }

        alert(data.msg);
        return false;
    } catch (err) {
        alert("Error de conexión");
        return false;
    }
}

// ----- LOGOUT -----
async function logout() {
    try {
        await fetch(API_URL + "/logout", {
            method: "POST",
            credentials: "include"
        });
    } catch (err) {
        console.error("Error al cerrar sesión:", err);
    }
    
    // ===== SINGLE-TAB SESSION: Limpiar tracking =====
    clearSessionTracking();
    
    window.location.href = "index.html";
}

// ----- CIFRAR TEXTO -----
async function encryptText(plainText) {
    try {
        const response = await fetch(API_URL + "/encrypt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ plainText })
        });

        const data = await response.json();
        return data;
    } catch (err) {
        return { ok: false, msg: "Error de conexión" };
    }
}

// ----- DESCIFRAR TEXTO -----
async function decryptText(cipher) {
    try {
        const response = await fetch(API_URL + "/decrypt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ cipher })
        });

        const data = await response.json();
        return data;
    } catch (err) {
        return { ok: false, msg: "Error de conexión" };
    }
}

// ----- GUARDAR CIFRADO -----
async function saveCipher(cipher) {
    try {
        const response = await fetch(API_URL + "/save-text", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ cipher })
        });

        return await response.json();
    } catch (err) {
        return { ok: false, msg: "Error de conexión" };
    }
}

// ----- OBTENER HISTORIAL -----
async function getMyTexts() {
    try {
        const response = await fetch(API_URL + "/my-texts", {
            method: "GET",
            credentials: "include"
        });

        return await response.json();
    } catch (err) {
        return { ok: false, msg: "Error de conexión" };
    }
}
