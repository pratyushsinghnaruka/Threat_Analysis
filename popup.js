document.addEventListener("DOMContentLoaded", () => {
  const closeButton = document.getElementById("close");

  if (closeButton) {
    closeButton.addEventListener("click", () => {
      window.close();  // Closes the popup window
    });
  }
});