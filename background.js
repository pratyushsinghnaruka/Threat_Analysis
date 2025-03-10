chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const url = changeInfo.url;

    checkUrlSafety(url).then((isSafe) => {
      if (!isSafe) {
        // Threat detected - show warning
        chrome.action.setIcon({
          path: {
            "16": "icons/warning.png",
            "48": "icons/warning.png",
            "128": "icons/warning.png"
          }
        });
        chrome.action.setPopup({ popup: "popup.html" });
      } else {
        // Site is safe - show safe icons
        chrome.action.setIcon({
          path: {
            "16": "icons/safe16.png",
            "48": "icons/safe48.png",
            "128": "icons/safe128.png"
          }
        });
        chrome.action.setPopup({ popup: "popup_safe.html" });
      }
    });
  }
});

// Function to check URL safety using your deployed API
async function checkUrlSafety(url) {
  const apiUrl = "https://threats-analysis.onrender.com/check_url";  // Your deployed Flask API endpoint

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    return !data.threat;  // Returns true if safe, false if threat detected
  } catch (error) {
    console.error("Error checking URL safety:", error);
    return true;  // Fail-safe: assume safe if error occurs
  }
}