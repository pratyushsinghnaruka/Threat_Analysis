chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const url = changeInfo.url;
    console.log("URL changed:", url);

    checkUrlSafety(url).then((data) => {
      if (data.error) {
        console.error("Threat detection failed:", data.error);
        return; // Do nothing else if there's an error
      }

      const probability = data.malicious_probability || 0;
      const isThreat = data.threat === true || probability > 50;

      // Log the decision
      console.log(`Checked URL: ${url}`);
      console.log(`Threat? ${isThreat}`);
      console.log(`Malicious Probability: ${probability}%`);

      // Safe site → green icon + popup_safe.html
      if (!isThreat) {
        chrome.action.setIcon({
          path: {
            "16": "icons/safe16.png",
            "48": "icons/safe48.png",
            "128": "icons/safe128.png"
          },
          tabId: tabId
        });

        chrome.action.setPopup({
          popup: "popup_safe.html",
          tabId: tabId
        });
      } 
      // Threat site → yellow icon + popup.html
      else {
        chrome.action.setIcon({
          path: {
            "16": "icons/warning16.png",
            "48": "icons/warning48.png",
            "128": "icons/warning128.png"
          },
          tabId: tabId
        });

        chrome.action.setPopup({
          popup: "popup.html",
          tabId: tabId
        });
      }

      // Save result in chrome.storage.local for the popup to display
      chrome.storage.local.set(
        {
          threatData: {
            url: data.url || url,
            message: data.message || "",
            malicious_probability: probability,
            threat: isThreat
          }
        },
        () => {
          if (chrome.runtime.lastError) {
            console.error("Error saving to storage:", chrome.runtime.lastError);
          } else {
            console.log("Threat data saved to storage:", {
              url: data.url || url,
              message: data.message,
              malicious_probability: probability,
              threat: isThreat
            });
          }
        }
      );
    });
  }
});

// Function to call your backend API and get threat data
async function checkUrlSafety(url) {
  const apiUrl = "https://threats-analysis.onrender.com/check_url"; // Your backend API endpoint

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      console.error(`API error (${response.status}): ${response.statusText}`);
      return { error: `API error (${response.status}): ${response.statusText}` };
    }

    const data = await response.json();
    console.log("API Response:", data);
    return data;

  } catch (error) {
    console.error("Error connecting to the API:", error);
    return { error: "Error connecting to the API" };
  }
}