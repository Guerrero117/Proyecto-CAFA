// Funciones de CRUD de usuarios usando localStorage

// Leer usuarios
function getUsers() {
    let users = localStorage.getItem('users');
    return users ? JSON.parse(users) : [];
}

// Guardar usuarios
function saveUsers(users) {
    localStorage.setItem('users', JSON.stringify(users));
}

// Create: Registrar usuario
function registerUser(username, password) {
    let users = getUsers();
    if(users.some(u => u.username === username)) {
        alert("Usuario ya existe");
        return false;
    }
    let hashedPassword = CryptoJS.SHA256(password).toString();
    users.push({ username, password: hashedPassword });
    saveUsers(users);
    alert("Usuario registrado correctamente");
    return true;
}

// Read: Validar login
function loginUser(username, password) {
    let users = getUsers();
    let hashedPassword = CryptoJS.SHA256(password).toString();
    let user = users.find(u => u.username === username && u.password === hashedPassword);
    if(user) {
        localStorage.setItem('loggedUser', username);
        return true;
    } else {
        alert("Usuario o contraseña incorrectos");
        return false;
    }
}

// Update: Cambiar contraseña
function updatePassword(username, newPassword) {
    let users = getUsers();
    let hashedPassword = CryptoJS.SHA256(newPassword).toString();
    users = users.map(u => {
        if(u.username === username) u.password = hashedPassword;
        return u;
    });
    saveUsers(users);
}

// Delete: Eliminar usuario
function deleteUser(username) {
    let users = getUsers();
    users = users.filter(u => u.username !== username);
    saveUsers(users);
}
