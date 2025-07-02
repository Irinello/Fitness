
function navigateTo(page) {
    if (page === 'Home') {
        window.location.href = 'index.html';  // Redirectioneaza la pagina principala
    } else if (page === 'subscriptions') {
        window.location.href = 'index.html#pricing';  // Redirectioneaza la pagina de abonamente
    }
}


//Afiseaza utilizatorii//
// Incarca utilizatorii//
document.addEventListener("DOMContentLoaded", loadUsers);

async function loadUsers() {
    try {
        const response = await fetch("http://127.0.0.1:5001/get_all_users", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();
        console.log("Rezultat utilizatori:", result); //  Verifica datele primite

        if (response.ok) {
            displayUsers(result.users);
            populateUserDropdown(result.users); //  Populeaza dropdown-ul
        } else {
            console.error("Eroare:", result.message);
        }
    } catch (error) {
        console.error("Eroare la obținerea utilizatorilor:", error);
    }
}

function displayUsers(users) {
    const userTableBody = document.querySelector(".user-table tbody"); // Selecteaza tbody-ul corect
    userTableBody.innerHTML = ""; // Curata continutul anterior

    const filteredUsers = users.filter(user => user.role !== "admin");

    if (filteredUsers.length === 0) {
        userTableBody.innerHTML = "<tr><td colspan='4'>Niciun utilizator găsit.</td></tr>";
        return;
    }

    filteredUsers.forEach(user => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${user.id}</td>
            <td>${user.full_name}</td>
            <td>${user.email}</td>
            <td>${user.subscription || "No subscription"}</td>
        `;
        userTableBody.appendChild(row);
    });
}

// ================ Modifica abonamentul utilizatorului ================== //

// Apeleaza funcția la încarcarea paginii
document.addEventListener("DOMContentLoaded", loadUsersForDropdown);

function searchUser() {
    let input = document.getElementById("search-user").value.toLowerCase();
    let rows = document.querySelectorAll("#user-list table tr");

    rows.forEach((row, index) => {
        if (index === 0) return; // Sare peste antetul tabelului
        let name = row.cells[1].textContent.toLowerCase();
        row.style.display = name.includes(input) ? "" : "none";
    });
}


async function updateSubscription() {
    const userId = document.getElementById("user-select-subscription").value;
    const newSubscription = document.getElementById("subscription").value;

    if (!userId || !newSubscription) {
        alert("Please select a user and a subscription!");
        return;
    }

    try {
        const response = await fetch("http://127.0.0.1:5001/update_user_subscription", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: userId,
                subscription: newSubscription,
            }),
        });

        const result = await response.json();

        if (response.ok) {
            alert("Subscription updated successfully!");
            loadUsers(); // Reincarca lista utilizatorilor pentru a reflecta schimbarea
        } else {
            alert("Error: " + result.message);
        }
    } catch (error) {
        console.error("Eroare la actualizarea abonamentului:", error);
    }
}


function populateUserDropdown(users) {
    const userSelect = document.getElementById("user-select-subscription");
    userSelect.innerHTML = ""; // Curăță dropdown-ul anterior

    const filteredUsers = users.filter(user => user.role !== "admin"); // Exclude adminul

    filteredUsers.forEach(user => { //   iteram prin `filteredUsers`
        const option = document.createElement("option");
        option.value = user.id;
        option.textContent = `${user.full_name} (${user.email})`; // Afiseaza nume și email
        userSelect.appendChild(option);
    });
}


async function loadUsersForDropdown() {  
    try {
        const response = await fetch("http://127.0.0.1:5001/get_all_users", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();
        console.log("Utilizatori pentru dropdown:", result); // Verificare în consolă

        if (response.ok) {
            populateUserDropdown(result.users); 
        } else {
            console.error("Eroare la încărcarea utilizatorilor:", result.message);
        }
    } catch (error) {
        console.error("Eroare la obținerea utilizatorilor pentru dropdown:", error);
    }
}



// ============= STERGE USER ===========//
// ============= Incarca utilizatori ========//

document.addEventListener("DOMContentLoaded", () => {
    loadUsers(); // Incarcăutilizatorii în tabel și dropdown
    populateUsers(); // Incarca utilizatorii pentru stergere
});

async function populateUsers() {
    const userSelect = document.getElementById("user-delete-select");
    userSelect.innerHTML = ""; // Golește dropdown-ul

    try {
        const response = await fetch("http://127.0.0.1:5001/get_users_to_Delete", {
            method: "GET",
            credentials: "include" // Permite autentificarea cu sesiuni/cookie
        });

        if (!response.ok) {
            if (response.status === 403) {
                alert("Nu ai permisiunea de a accesa această funcție!");
            } else {
                throw new Error(`Eroare server: ${response.status}`);
            }
            return;
        }

        const data = await response.json();
        const users = data.users;

        if (!Array.isArray(users) || users.length === 0) {
            console.warn("Niciun utilizator de șters!");
            let option = document.createElement("option");
            option.textContent = "Niciun utilizator disponibil";
            option.disabled = true;
            userSelect.appendChild(option);
            return;
        }

        users.forEach(user => {
            let option = document.createElement("option");
            option.value = user.id;
            option.textContent = user.full_name;
            userSelect.appendChild(option);
        });

    } catch (error) {
        console.error("Eroare la obținerea utilizatorilor:", error);
    }
}

async function EraseUser() {
    const userSelect = document.getElementById("user-delete-select");
    const userId = userSelect.value;

    if (!userId) {
        alert("Selectează un utilizator!");
        return;
    }

    if (!confirm(`Sigur vrei să ștergi acest utilizator?`)) {
        return;
    }

    try {
        const response = await fetch(`http://127.0.0.1:5001/delete_user/${userId}`, {
            method: "DELETE",
            credentials: "include" // Permite autentificarea cu sesiuni
        });

        const result = await response.json();
        
        if (response.ok) {
            alert(result.message || "Utilizator șters cu succes!");
            populateUsers(); // Reincarca lista după stergere
        } else {
            alert(result.message || "Eroare la ștergere!");
        }
    } catch (error) {
        console.error("Eroare la ștergere:", error);
        alert("Eroare la ștergerea utilizatorului!");
    }
}

// ========== LOG OUT ============ //

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
