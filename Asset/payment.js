
//Confirmarea platii
async function confirmPayment() {
    if (!validatePaymentForm()) {
        return;
    }

    // Ascundem mesajele de fiecare data când se încearcă trimiterea
    document.getElementById("successMessage").style.display = "none";
    document.getElementById("errorMessage").style.display = "none";

    const formData = {
        card_name: document.getElementById("card_name").value,
        card_number: document.getElementById("card_number").value,
        exp_month: document.getElementById("exp_month").value,
        exp_year: document.getElementById("exp_year").value,
        cvv: document.getElementById("cvv").value,
        full_name: document.getElementById("full_name").value,
        email: document.getElementById("email").value,
        address: document.getElementById("address").value,
        city: document.getElementById("city").value,
        state: document.getElementById("state").value,
        zip: document.getElementById("zip_code").value
    };

    try {
        const response = await fetch("http://127.0.0.1:5001/payment", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify(formData)
        });

        if (response.redirected) {
            document.getElementById("successMessage").style.display = "block";
            setTimeout(() => {
                window.location.href = response.url;
            }, 2000); 
        } else {
            const result = await response.text();
            document.getElementById("errorMessage").textContent = "Payment failed: " + result;
            document.getElementById("errorMessage").style.display = "block";
        }
    } catch (error) {
        console.error("Eroare la confirmarea plății:", error);
        document.getElementById("errorMessage").textContent = "A apărut o eroare la procesarea plății.";
        document.getElementById("errorMessage").style.display = "block";
    }
}





//Erorile 

function showError(input, message) {
    input.classList.add("error");
    const errorText = input.nextElementSibling;
    if (errorText && errorText.tagName.toLowerCase() === "small") {
        errorText.textContent = message;
        errorText.style.display = "block";
    }
}


function clearErrors() {
    document.querySelectorAll(".input_box").forEach(box => {
        box.classList.remove("error");
        const small = box.querySelector("small");
        if (small) small.innerText = "";
    });
}

function clearErrorOnInput(input) {
    input.addEventListener("input", () => {
        input.classList.remove("error");
        const errorText = input.nextElementSibling;
        if (errorText && errorText.tagName.toLowerCase() === "small") {
            errorText.style.display = "none";
        }
    });
}



function validatePaymentForm() {
    clearErrors();
    let valid = true;
    const yearNow = new Date().getFullYear();

    const fields = {
        card_name: "Please enter the cardholder's name.",
        card_number: "Card number must be exactly 16 digits.",
        exp_month: "Please enter the expiration month.",
        exp_year: "Expiration year must be this year or later.",
        cvv: "CVV must be exactly 3 digits.",
        full_name: "Please enter your full name.",
        email: "Invalid email format.",
        address: "Please enter your full address.",
        city: "Please enter your city.",
        state: "Please enter your country.",
        zip_code: "Please enter your zip code."
    };

    const values = {};
    for (let key in fields) {
        values[key] = document.getElementById(key).value.trim();
    }

    if (!values.card_name) {
        showError(document.getElementById("card_name"), fields.card_name);
        valid = false;
    }
    
    if (!/^\d{16}$/.test(values.card_number)) {
        showError(document.getElementById("card_number"), fields.card_number);
        valid = false;
    }
    
    if (!values.exp_month) {
        showError(document.getElementById("exp_month"), fields.exp_month);
        valid = false;
    }
    
    const expYear = parseInt(values.exp_year);
    if (isNaN(expYear) || expYear < yearNow) {
        showError(document.getElementById("exp_year"), fields.exp_year);
        valid = false;
    }
    
    
    if (!/^\d{3}$/.test(values.cvv)) {
        showError(document.getElementById("cvv"), fields.cvv);
        valid = false;
    }
    
    if (!values.full_name) {
        showError(document.getElementById("full_name"), fields.full_name);
        valid = false;
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) {
        showError(document.getElementById("email"), fields.email);
        valid = false;
    }
    
    if (!values.address) {
        showError(document.getElementById("address"), fields.address);
        valid = false;
    }
    
    if (!values.city) {
        showError(document.getElementById("city"), fields.city);
        valid = false;
    }
    
    if (!values.state) {
        showError(document.getElementById("state"), fields.state);
        valid = false;
    }
    
    if (!values.zip_code) {
        showError(document.getElementById("zip_code"), fields.zip_code);
        valid = false;
    }
    
    return valid;
}

document.addEventListener("DOMContentLoaded", () => {
    const inputs = [
        "card_name", "card_number", "exp_month", "exp_year", "cvv",
        "full_name", "email", "address", "city", "state", "zip_code"
    ];

    inputs.forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            clearErrorOnInput(input);
        }
    });
});
