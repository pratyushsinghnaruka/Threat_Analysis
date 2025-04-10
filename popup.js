document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.local.get(['threatData'], function(result) {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      return;
    }

    if (result && result.threatData) {
      const { malicious_probability, genai_analysis } = result.threatData;

      if (malicious_probability !== undefined) {
        const probabilityPercentage = (malicious_probability * 100).toFixed(2);
        document.getElementById('probability').innerText = probabilityPercentage + "%";
      } else {
        document.getElementById('probability').innerText = "Unknown";
      }

      // Show GenAI analysis if available
      if (genai_analysis) {
        document.getElementById('genaiText').innerText = genai_analysis;
        document.getElementById('genaiAnalysis').style.display = 'block';
      }
    } else {
      console.log('No threat data found.');
    }
  });

  document.getElementById('closeBtn').addEventListener('click', function() {
    window.close();
  });
});
