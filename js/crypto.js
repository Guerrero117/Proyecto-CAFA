// Clave para AES (puede derivarse de la contraseña)
const key = "clave_super_secreta";

// Create: Guardar texto encriptado
function saveEncryptedText(plainText) {
    let texts = getEncryptedTexts();
    let ciphertext = CryptoJS.AES.encrypt(plainText, key).toString();
    texts.push({ id: Date.now(), cipher: ciphertext });
    localStorage.setItem('texts', JSON.stringify(texts));
    return ciphertext;
}

// Read: Obtener todos los textos encriptados
function getEncryptedTexts() {
    let texts = localStorage.getItem('texts');
    return texts ? JSON.parse(texts) : [];
}

// Update: Actualizar un texto encriptado
function updateEncryptedText(id, newPlainText) {
    let texts = getEncryptedTexts();
    let ciphertext = CryptoJS.AES.encrypt(newPlainText, key).toString();
    texts = texts.map(t => {
        if(t.id === id) t.cipher = ciphertext;
        return t;
    });
    localStorage.setItem('texts', JSON.stringify(texts));
}

// Delete: Eliminar un texto encriptado
function deleteEncryptedText(id) {
    let texts = getEncryptedTexts();
    texts = texts.filter(t => t.id !== id);
    localStorage.setItem('texts', JSON.stringify(texts));
}

// Desencriptar
function decryptText(cipher) {
    let bytes = CryptoJS.AES.decrypt(cipher, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}
