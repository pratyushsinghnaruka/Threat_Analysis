document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['threatData'], (result) => {
    if (chrome.runtime.lastError) {
      console.error("Storage error:", chrome.runtime.lastError);
      return;
    }

    const threatData = result?.threatData;
    if (!threatData) {
      console.log('No threat data found.');
      return;
    }

    const { malicious_probability, genai_analysis } = threatData;

    // Display probability
    const probabilityEl = document.getElementById('probability');
    if (malicious_probability !== undefined) {
      probabilityEl.innerText = (malicious_probability * 100).toFixed(2) + "%";
    } else {
      probabilityEl.innerText = "Unknown";
    }

    // Display GenAI analysis
    if (genai_analysis) {
      const genaiBox = document.getElementById('genaiAnalysis');
      const genaiTextEl = document.getElementById('genaiText');
      const genaiVerifiedEl = document.getElementById('genai-verified');

      genaiTextEl.innerText = genai_analysis;

      // Highlight key danger words
      const alertKeywords = ["phishing", "malicious", "unsafe", "fake login", "flagged as malicious"];
      const alertDetected = alertKeywords.some(word => genai_analysis.toLowerCase().includes(word));

      if (alertDetected) {
        genaiTextEl.style.color = "red";
        genaiTextEl.style.fontWeight = "bold";
      }

      if (genai_analysis.length > 50) {
        genaiVerifiedEl.style.display = "inline-block";
      }

      genaiBox.style.display = "block";
    }
  });

  document.getElementById('closeBtn').addEventListener('click', () => {
    window.close();
  });
});
