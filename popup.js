document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.local.get(['threatData'], function(result) {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      return;
    }

    if (result && result.threatData) {
      const { url, message, malicious_probability } = result.threatData;

      document.getElementById('url').innerText = url || "Unknown";
      document.getElementById('message').innerText = message || "No message";

      // Only display probability if it's defined
      if (malicious_probability !== undefined) {
        const probabilityPercentage = (malicious_probability * 100).toFixed(2);
        document.getElementById('probability').innerText = probabilityPercentage + "%";
      } else {
        document.getElementById('probability').innerText = "Unknown";
      }

    } else {
      console.log('No threat data found.');
    }
  });

  document.getElementById('closeBtn').addEventListener('click', function() {
    window.close();
  });
});