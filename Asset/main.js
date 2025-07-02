/*=============== SHOW MENU ===============*/
const navMenu = document.getElementById('nav-menu'),
    navToggle = document.getElementById('nav-toggle'),
    navClose = document.getElementById('nav-close')


/*======= MENU SHOW ======*/
/* Validate if constant exist */

if (navToggle) {
    navToggle.addEventListener('click', () => {
        navMenu.classList.add('show-menu')
    })
}

/*======= MENU HIDDEN ======== */
/* Validate if constant exist */
if (navClose) {
    navClose.addEventListener('click', () => {
        navMenu.classList.remove('show-menu')
    })
}
/*=============== REMOVE MENU MOBILE ===============*/
const navLink = document.querySelectorAll('.nav__link')

const linkAction = () => {
    const navMenu = document.getElementById('nav-menu')
    navMenu.classList.remove('show-menu')
}
navLink.forEach(n => n.addEventListener('click', linkAction))

/*=============== CHANGE BACKGROUND HEADER ===============*/
const scrollHeader = () => {
    const header = document.getElementById('header');
    window.scrollY >= 50 ? header.classList.add('bg-header')
        : header.classList.remove('bg-header');
};

window.addEventListener('scroll', scrollHeader);

/*=============== SCROLL SECTIONS ACTIVE LINK ===============*/
const sections = document.querySelectorAll('section[id]');

const scrollActive = () => {
    const scrollY = window.pageYOffset;

    sections.forEach(current => {
        const sectionHeight = current.offsetHeight, // corectat aici
            sectionTop = current.offsetTop - 58,
            sectionId = current.getAttribute('id'),
            sectionClass = document.querySelector('.nav__menu a[href*="' + sectionId + '"]'); 

        if (scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) {
            sectionClass.classList.add('active-link');
        } else {
            sectionClass.classList.remove('active-link');
        }
    });
}

window.addEventListener('scroll', scrollActive);

/*=============== SHOW SCROLL UP ===============*/
const scrollUp = () => {
    const scrollUp = document.getElementById('scroll-up');
    if (window.scrollY >= 350) { // Verificăm dacă scrollY este mai mare sau egal cu 350
        scrollUp.classList.add('show-scroll'); // Adăugăm clasa pentru a afișa elementul
    } else {
        scrollUp.classList.remove('show-scroll'); // Eliminăm clasa dacă scrollY este mai mic
    }
};

window.addEventListener('scroll', scrollUp);

/*=============== SCROLL REVEAL ANIMATION ===============*/
const sr = ScrollReveal({
    origin: 'top',
    distance: '60px',
    duration: 2500,
    delay: 400,

});

sr.reveal('.home__data, .footer__container,.footer__group, .footer__description')
sr.reveal('.home__img', { delay: 700, origin: 'right' })
sr.reveal('.logos__img, .program__card, .pricing__card, .point__article', { interval: 150 })
sr.reveal('.choose__img, .calculate__content', { origin: 'left' })
sr.reveal('.choose__content, .calculate__img', { origin: 'right' })


/*=============== CALCULATE JS ===============*/
const calculateForm = document.getElementById('calculate-form'),
    calculateCm = document.getElementById('calculate-cm'),
    calculateKg = document.getElementById('calculate-kg'),
    calculateMessage = document.getElementById('calculate-message')

const calculateBmi = (e) => {
    e.preventDefault()

    //Check if the fields have a value
    if (calculateCm.value === '' || calculateKg.value === '') {
        //Add and remove color 
        calculateMessage.classList.remove('color-green')
        calculateMessage.classList.add('color-red')

        //Show Message
        calculateMessage.textContent = 'Enter Your Height and Weight 📏⚖️ '

        //Remove message 
        setTimeout(() => {
            calculateMessage.textContent = ''
        }, 3000)

    } else {
        //Bmi formula
        const cm = calculateCm.value / 100,
            kg = calculateKg.value,
            bmi = Math.round(kg / (cm * cm))

        //Health status
        if (bmi < 18.5) {
            calculateMessage.classList.add('color-red')
            calculateMessage.textContent = `BMI ${bmi} To Skinny`
        } else if (bmi < 25) {
            calculateMessage.classList.add('color-green')
            calculateMessage.textContent = `BMI ${bmi} You're Healty`
        } else {
            calculateMessage.classList.add('color-green')
            calculateMessage.textContent = `BMI ${bmi} Overweight `
        }

        calculateCm.value = ''
        calculateKg.value = ''

        setTimeout(() => {
            calculateMessage.textContent = ''
        }, 4000)
    }
}

calculateForm.addEventListener('submit', calculateBmi)

// Registration

document.addEventListener("DOMContentLoaded", function () {
    // 🔹 Elementele din pagină
    const registerBtn = document.getElementById("registerBtn");
    const loginBtn = document.getElementById("loginBtn");
    const registerForm = document.getElementById("registerForm");
    const loginForm = document.getElementById("loginForm");
    const registrationForm = document.getElementById("registrationForm");
    const errorMessage = document.getElementById("errorMessage");
    const successMessage = document.getElementById("successMessage");

    //  Switch între formulare: Register / Login
    if (registerBtn && loginBtn) {
        registerBtn.addEventListener("click", function () {
            clearMessages();
            registerForm.style.display = "block";
            loginForm.style.display = "none";
            registerBtn.classList.add("active");
            loginBtn.classList.remove("active");
        });

        loginBtn.addEventListener("click", function () {
            clearMessages();
            registerForm.style.display = "none";
            loginForm.style.display = "block";
            loginBtn.classList.add("active");
            registerBtn.classList.remove("active");
        });
    }

    //  Verifica sesiunea la incarcarea paginii
    checkSession();

    async function checkSession() {
        try {
            const response = await fetch("http://127.0.0.1:5001/check_session", {
                method: "GET",
                credentials: "include",
            });

            const result = await response.json();
            if (result.success) {
                console.log("User is logged in:", result.user);
                
            } else {
                console.log("User not logged in.");
            }
        } catch (error) {
            console.error("Session check error:", error);
        }
    }

    // Trimite datele de înregistrare
    if (registrationForm) {
        registrationForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            clearMessages();
            clearFieldErrors();

            const fullName = document.getElementById("fullName").value.trim();
            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;
            const confirmPassword = document.getElementById("confirmPassword").value;
            const gender = document.querySelector('input[name="gender"]:checked')?.value;

            let hasError = false;

            if (!fullName) {
                showFieldError("fullName", "Full name is required.");
                hasError = true;
            } else if (fullName.split(" ").length < 2) {
                showFieldError("fullName", "Please enter both first and last name.");
                hasError = true;
            }
            if (!email) {
                showFieldError("email", "Email is required.");
                hasError = true;
            }

            if (!password) {
                showFieldError("password", "Password is required.");
                hasError = true;
            }

            if (!confirmPassword) {
                showFieldError("confirmPassword", "Please confirm your password.");
                hasError = true;
            }

            const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
            if (password && !passwordRegex.test(password)) {
                showFieldError("password", "Password must be at least 8 characters, include an uppercase letter, number, and special character.");
                hasError = true;
            }

            if (password && confirmPassword && password !== confirmPassword) {
                showFieldError("confirmPassword", "Passwords do not match.");
                hasError = true;
            }

            if (!gender) {
                showFieldError("gender", "Gender is required.");
                hasError = true;
            }

            if (hasError) return;

            try {
                const response = await fetch("http://127.0.0.1:5001/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ fullName, email, password, gender }),
                });

                const result = await response.json();
                clearMessages();

                if (response.ok) {
                    showSuccess.innerText = "Account created successfully!";
                    registrationForm.reset();
            
                    setTimeout(() => {
                        document.getElementById("loginBtn")?.click();
                    }, 3000);
                } else {
                    showError(result.message || "Registration failed.");
                }
            } catch (error) {
                console.error("Registration error:", error);
                showError("An error occurred. Please try again.");
            }

            setTimeout(() => {
                clearMessages();
            }, 10000);
        });
    }

    // Verifica dacă email-ul exista deja 
        const emailInput = document.getElementById("email");
        if (emailInput) {
            emailInput.addEventListener("blur", async () => {
                const email = emailInput.value.trim();
                if (!email) return;
    
                try {
                    const response = await fetch("http://127.0.0.1:5001/check_email", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email }),
                    });
    
                    const result = await response.json();
                    if (result.exists) {
                        showFieldError("email", "This email is already in use.");
                    }
                } catch (error) {
                    console.error("Email check error:", error);
                }
            });
        }
    
    

    function showFieldError(fieldId, message) {
        const tooltip = document.getElementById(fieldId + "Error");
        if (tooltip) {
            tooltip.innerText = message;
            tooltip.style.display = "block";
        }
    }

    function clearFieldErrors() {
        const fields = ["fullName", "email", "password", "confirmPassword", "gender"];
        fields.forEach(field => {
            const errorSpan = document.getElementById(field + "Error");
            if (errorSpan) errorSpan.style.display = "none";
        });
    }

    function showError(message) {
        if (errorMessage) {
            errorMessage.innerText = message;
        }
    }

    function clearMessages() {
        if (errorMessage) errorMessage.innerText = "";
        if (successMessage) successMessage.innerText = "";
    }

    
    ["fullName", "email", "password", "confirmPassword"].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener("input", () => {
                const errorSpan = document.getElementById(id + "Error");
                if (errorSpan) errorSpan.style.display = "none";
            });
        }
    });

    
    document.querySelectorAll('input[name="gender"]').forEach(radio => {
        radio.addEventListener("change", () => {
            const errorSpan = document.getElementById("genderError");
            if (errorSpan) errorSpan.style.display = "none";
        });
    });

    
    function showTooltip(message, type = "error") {
        const tooltip = document.getElementById("globalTooltip");
        if (!tooltip) return;
    
        tooltip.innerText = message;
        tooltip.classList.remove("success", "error");
        tooltip.classList.add(type);
        tooltip.style.display = "block";
    
        setTimeout(() => {
            tooltip.style.display = "none";
        }, 5000);
    }
    
    function showError(message) {
        showTooltip(message, "error");
    }
    
    function showSuccess(message) {
        showTooltip(message, "success");
    }



    
    // Login

        const loginFormElement = document.getElementById("loginFormElement");
        if (loginFormElement) {
            loginFormElement.addEventListener("submit", async function (event) {
            event.preventDefault();

            const email = document.getElementById("loginEmail").value.trim();
            const password = document.getElementById("loginPassword").value;
            const errorMessage = document.getElementById("Login-error-message");

            if (!email || !password) {
                errorMessage.innerText = "All fields are required!";
                return;
            }

            try {
                const response = await fetch("http://127.0.0.1:5001/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password }),
                    credentials: "include"
                });

                const result = await response.json();

                if (result.success) {
                   if (result.role === 'admin') {
                         window.location.href = "http://127.0.0.1:5500/admin.html";
                    } else if (result.is_new_user) {
                        window.location.href = "http://127.0.0.1:5500/beginner.html";
                    } else {
                        window.location.href = "http://127.0.0.1:5500/index.html";
                    }
                } else {
                    errorMessage.innerText = result.message;
                }

                
            } catch (error) {
                console.error("Login error:", error);
                errorMessage.innerText = "An error occurred. Please try again.";
            }
        });
    }

});