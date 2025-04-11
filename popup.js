document.addEventListener('DOMContentLoaded', function () {
  chrome.storage.local.get(['threatData'], function (result) {
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

      if (genai_analysis) {
        const genaiTextEl = document.getElementById('genaiText');
        const genaiVerifiedEl = document.getElementById('genai-verified');
        const text = genai_analysis;

        // ✅ Highlight strong GenAI alerts in red
        if (
          text.toLowerCase().includes("phishing") ||
          text.toLowerCase().includes("fake login") ||
          text.toLowerCase().includes("malicious") ||
          text.toLowerCase().includes("unsafe") ||
          text.toLowerCase().includes("flagged as malicious")
        ) {
          genaiTextEl.style.color = "red";
          genaiTextEl.style.fontWeight = "bold";
        }

        genaiTextEl.innerText = text;

        if (text.length > 50) {
          genaiVerifiedEl.style.display = "inline-block";
        }

        document.getElementById('genaiAnalysis').style.display = 'block';
      }
    } else {
      console.log('No threat data found.');
    }
  });

  document.getElementById('closeBtn').addEventListener('click', function () {
    window.close();
  });
});
