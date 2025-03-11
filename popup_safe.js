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
      
    } else {
      console.log('No threat data found.');
    }
  });

  document.getElementById('closeBtn').addEventListener('click', function() {
    window.close();
  });
});