// Usar rutas relativas (mismo dominio)
const API_URL = "";

// ----- VERIFICAR AUTENTICACIÓN -----
async function verifyAuth() {
    try {
        const response = await fetch(API_URL + "/verify-auth", {
            method: "GET",
            credentials: "include" // Incluir cookies
        });
        const data = await response.json();
        return data.ok;
    } catch (err) {
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
