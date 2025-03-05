// Listen for URL changes in active tabs
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
      const url = changeInfo.url;
      checkUrlSafety(url).then((isSafe) => {
        if (!isSafe) {
          // Show warning icon and popup
          chrome.action.setIcon({ path: "icons/warning.png" });
          chrome.action.setPopup({ popup: "popup.html" });
        } else {
          // Show safe icon
          chrome.action.setIcon({ path: "icons/safe.png" });
        }
      });
    }
  });
  
  // Function to check URL safety using an API
    // Replace with your API endpoint or AI model
    async function checkUrlSafety(url) {
        const apiKey = "YOUR_API_KEY";
        const apiUrl = https //safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey};
        const response = await fetch(apiUrl, {
          method: "POST",
          body: JSON.stringify({
            client: { clientId: "threat-detector", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }],
            },
          }),
        });
        const result = await response.json();
        return result.matches ? false : true; // Safe if no matches
      }