function goHome() {
  window.location.href = '/index.html';
}


emailjs.init("_M9vXce1CbwB3swwV");

document.getElementById("contact-form").addEventListener("submit", function (event) {
  event.preventDefault();

  const name = document.querySelector("#name").value.trim();
  const email = document.querySelector("#email").value.trim();
  const subject = document.querySelector("#subject").value.trim();
  const message = document.querySelector("#message").value.trim();
  const statusMessage = document.getElementById("status-message");

  statusMessage.style.display = "none";
  statusMessage.className = "";

  // Verificare cAmpuri goale
  if (!name || !email || !subject || !message) {
    showMessage("Please fill all quest.", "error");
    return;
  }

  // Verificare ca numele să contină cel putin doua cuvinte
  const nameParts = name.split(" ");
  if (nameParts.length < 2) {
    showMessage("Please insert Full Name.", "error");
    return;
  }

  // Verificare simpla format email 
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    showMessage("Please insert a valid E-mail.", "error");
    return;
  }

  // 
  const serviceID = "service_hwv9hgx";
  const templateID = "template_hewu3si";

  const params = {
    from_name: name,
    from_email: email,
    subject: subject,
    message: message,
    reply_to: email
  };

  emailjs.send(serviceID, templateID, params)
    .then(() => {
      showMessage("The message has been sent successfully. ", "success");
      document.getElementById("contact-form").reset();
    })
    .catch((error) => {
      showMessage("Error, can't send.", "error");
      console.error("EmailJS error:", error);
    });
});

function showMessage(message, type) {
  const statusMessage = document.getElementById("status-message");
  statusMessage.textContent = message;

  // Aplicam clasa pentru tooltip + success/eroare
  statusMessage.className = `tooltip-message ${type}`;
  statusMessage.style.display = "inline-block";

  setTimeout(() => {
    statusMessage.style.opacity = "1";
    setTimeout(() => {
      statusMessage.style.opacity = "0";
      setTimeout(() => {
        statusMessage.style.display = "none";
      }, 300);
    }, 3000); // Vizibil 3 secunde
  }, 10);
}

