function goHome() {
    window.location.href = '/index.html';
}


/*=============== Video ===============*/

document.querySelectorAll(".workout-video").forEach(video => {
    video.addEventListener("mouseenter", () => {
        video.play();

    });
    video.addEventListener("mouseleave", () => {
        video.pause();
        video.currentTime = 0;
    });
});

/*=============== SHOW SCROLL UP ===============*/
const scrollUp = () => {
    const scrollUp = document.getElementById('scroll-up');
    if (window.scrollY >= 350) { // Verificăm dacă scrollY este mai mare sau egal cu 350
        scrollUp.classList.add('show-scroll'); // Adaugam clasa pentru a afisa elementul
    } else {
        scrollUp.classList.remove('show-scroll'); // Eliminam clasa dacă scrollY este mai mic
    }
};

window.addEventListener('scroll', scrollUp);

const sr = ScrollReveal({
    origin: 'top',
    distance: '60px',
    duration: 2500,
    delay: 400,

});



sr.reveal('.introduction, .strecing');
sr.reveal('.video-container', { delay: 700, origin: 'right' });
sr.reveal('.video-description', { delay: 700, origin: 'right' });


// Redirectioneaza utilizatorii neautentificati

document.addEventListener("DOMContentLoaded", async function () {
    try {
        const response = await fetch("http://127.0.0.1:5001/check_session", {
            method: "GET",
            credentials: "include",
        });

        const result = await response.json();
        if (!result.success) {
            window.location.href = "index.html";  // Redirecționeaza utilizatorii neautentificayi
        }
    } catch (error) {
        console.error("Session check error:", error);
    }
});


// Functia logout

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
