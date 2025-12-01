const API_URL = "https://sausagelike-nova-bridally.ngrok-free.dev";



// ----- REGISTRO -----
async function registerUser(username, password) {
    const response = await fetch(API_URL + "/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    alert(data.msg);

    if (data.ok) window.location.href = "index.html";
}

// ----- LOGIN -----
async function loginUser(username, password) {
    const response = await fetch(API_URL + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (data.ok) {
        localStorage.setItem("token", data.token);
        localStorage.setItem("userId", data.userId);
        return true;
    }

    alert(data.msg);
    return false;
}

// ----- GUARDAR CIFRADO -----
async function saveCipher(cipher) {
    const response = await fetch(API_URL + "/save-text", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": localStorage.getItem("token")
        },
        body: JSON.stringify({ cipher })
    });

    return await response.json();
}

// ----- OBTENER HISTORIAL -----
async function getMyTexts() {
    const response = await fetch(API_URL + "/my-texts", {
        method: "GET",
        headers: {
            "Authorization": localStorage.getItem("token")
        }
    });

    return await response.json();
}
