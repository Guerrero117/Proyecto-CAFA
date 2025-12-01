// crypto.js
const key = "clave_super_secreta_123";

// Encriptar texto plano
function encryptText(plain) {
    if (!plain) return "**No se recibió texto**";
    try {
        return CryptoJS.AES.encrypt(plain, key).toString();
    } catch (e) {
        console.error("Error al encriptar:", e);
        return "**Error al encriptar**";
    }
}

// Desencriptar texto cifrado
function decryptText(cipher) {
    if (!cipher) return "**No se recibió texto**";
    try {
        const bytes = CryptoJS.AES.decrypt(cipher.trim(), key);
        const plain = bytes.toString(CryptoJS.enc.Utf8);
        return plain || "**Texto inválido o llave incorrecta**";
    } catch (e) {
        console.error("Error al desencriptar:", e);
        return "**Error al desencriptar**";
    }
}
