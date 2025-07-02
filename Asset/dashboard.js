function goHome() {
    window.location.href = '/index.html';
}
function closeModal() {
    document.getElementById("subscription-modal").style.display = "none";
  }
  
// Update Statistici

async function updateStats() {
    let weight = document.getElementById("weight").value;
    let goal = document.getElementById("goal").value;

    if (!weight || !goal) {
        alert("Completează toate câmpurile!");
        return;
    }

    try {
        const response = await fetch("http://127.0.0.1:5001/update_stats", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ weight, goal }),
        });

        const result = await response.json();
        alert(result.message);
    } catch (error) {
        console.error("Eroare la salvarea statisticilor:", error);
    }
}

//Incarca statistici

async function loadStats() {
    try {
        const response = await fetch("http://127.0.0.1:5001/get_stats", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();
        console.log("Date primite de la backend:", result); // Debugging

        // Verifică dacă există date înainte de a le seta
        if (result.weight !== null && result.goal !== null) {
            document.getElementById("weight").value = result.weight;
            document.getElementById("goal").value = result.goal;
        }
    } catch (error) {
        console.error("Eroare la încărcarea statisticilor:", error);
    }
}

// Apelează această funcție când pagina de dashboard se încarcă
document.addEventListener("DOMContentLoaded", loadStats);


// Controleaza Subscriptia


async function checkSubscription() {
    try {
        const response = await fetch("http://127.0.0.1:5001/check_subscription", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();

        if (!result.subscription || result.subscription === "None" || result.subscription === null) {  
            document.getElementById("subscription-modal").style.display = "flex"; // Afișare corectă, centrat
        } else {
            document.getElementById("subscription-modal").style.display = "none"; // Ascunde dacă are abonament
        }
    } catch (error) {
        console.error("Eroare la verificarea abonamentului:", error);
    }
}    

// Verifică abonamentul la încărcarea paginii
document.addEventListener("DOMContentLoaded", function () {
    checkSubscription();   // Verifică dacă are abonament
    loadSubscription();    // Încarcă abonamentul și data de expirare
});

// Salveaza subscriptia initiala

async function saveInitialSubscription() {
    let selectedSubscription = document.getElementById("new-subscription").value;

    try {
        const response = await fetch("http://127.0.0.1:5001/initiate_payment", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ subscription: selectedSubscription }),
        });

        if (response.redirected) {
            window.location.href = response.url;  // Redirecționează către pagina de plată
        } else {
            const result = await response.json();
            alert("Error: " + result.message);
        }
    } catch (error) {
        console.error("Eroare la inițializarea plății:", error);
    }
}



// Face update la subscriptie

async function updateSubscription() {
    const newSubscription = document.getElementById("subscription").value;

    try {
        const response = await fetch("http://127.0.0.1:5001/initiate_payment", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ subscription: newSubscription })
        });

        if (response.redirected) {
            window.location.href = "http://127.0.0.1:5001/payment";  // Redirecționează către pagina de plată
        } else {
            const result = await response.json();
            alert("Error: " + result.message);
        }
    } catch (error) {
        console.error("Eroare la inițializarea plății:", error);
    }
}


// Incarca subscriptia

async function loadSubscription() {
    try {
        const response = await fetch("http://127.0.0.1:5001/get_subscription", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();

        if (result.subscription) {
            document.getElementById("current-subscription").innerText = result.subscription;

            if (result.expiry) {
                document.getElementById("expiry-date").innerText = result.expiry;
            }
        }
    } catch (error) {
        console.error("Eroare la încărcarea abonamentului:", error);
    }
}




//  Apelează această funcție la încărcarea paginii

// Schimba parola 

document.getElementById("changePasswordForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const messageBox = document.getElementById("passwordMessage");

    if (!currentPassword || !newPassword || !confirmPassword) {
        messageBox.innerText = "All fields are required!";
        return;
    }

    if (newPassword !== confirmPassword) {
        messageBox.innerText = "New passwords do not match!";
        return;
    }

    try {
        const response = await fetch("http://127.0.0.1:5001/change_password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ currentPassword, newPassword })
        });

        const result = await response.json();
        messageBox.innerText = result.message;

        if (result.success) {
            alert("Password changed successfully!");
            document.getElementById("changePasswordForm").reset();
        }
    } catch (error) {
        console.error("Error changing password:", error);
        messageBox.innerText = "An error occurred. Please try again.";
    }
});

 // Conroloeaza sesiunea si redirectioneaza la login

 async function checkSessionAndRedirect() {
    try {
        const response = await fetch("http://127.0.0.1:5001/check_session", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();

        if (!result.success) {
            // Dacă utilizatorul nu e logat, redirecționează-l la login
            window.location.href = "index.html";
        }
    } catch (error) {
        console.error("Error checking session:", error);
        window.location.href = "index.html"; // Redirecționează dacă există o eroare
    }
}

// Apeleaza funcția imediat după ce pagina s-a încărcat
document.addEventListener("DOMContentLoaded", checkSessionAndRedirect);

// Incarca userii


async function loadUserInfo() {
    try {
        const response = await fetch("http://127.0.0.1:5001/get_user_info", {
            method: "GET",
            credentials: "include",
        });

        if (response.status === 401) {
            window.location.href = "login.html";
            return;
        }

        const result = await response.json();

        if (result.success) {
            document.getElementById("username").innerText = result.full_name;
            document.getElementById("email").innerText = result.email;

            // Seteaza poza de profil în funcție de gen
            const gender = result.gender; // asigură-te că backend-ul trimite `gender`

            if (gender === "female") {
                document.getElementById("profile-icon").src = "Photo/women.png";
            } else {
                document.getElementById("profile-icon").src = "Photo/man.png";
            }
        } else {
            console.error("Failed to fetch user info:", result.message);
        }
    } catch (error) {
        console.error("Error loading user info:", error);
    }
}



// 🔹 Apelează funcția imediat după ce pagina s-a încărcat
document.addEventListener("DOMContentLoaded", loadUserInfo);

// Functia de logout

async function logout() {
    try {
        await fetch("http://127.0.0.1:5001/logout", {
            method: "POST",
            credentials: "include",
        });
    } catch (error) {
        console.error("Eroare la logout:", error);
    }
    window.location.href = "/index.html";
}