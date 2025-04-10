chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const url = changeInfo.url;
    console.log("🔄 URL changed:", url);

    if (isGoogleSearch(url)) {
      console.log("🔹 Google Search detected. Marking as safe.");

      chrome.action.setIcon({
        path: {
          "16": "icons/safe16.png",
          "48": "icons/safe48.png",
          "128": "icons/safe128.png",
        },
        tabId: tabId,
      });

      chrome.action.setPopup({
        popup: "popup_safe.html",
        tabId: tabId,
      });

      chrome.storage.local.set({
        threatData: {
          url: url,
          message: "Google Search is always safe.",
          malicious_probability: 0,
          threat: false,
          dataset: false,
        },
      });
      return;
    }

    checkUrlSafety(url)
      .then((data) => {
        if (data.error) {
          console.error("⚠️ Threat detection failed:", data.error);
          return;
        }

        const probability = typeof data.malicious_probability === "number" ? data.malicious_probability : 0;
        const isDatasetThreat = data.dataset === true;
        const isThreat = isDatasetThreat || data.threat === true || probability > 50;
        const genaiText = data.genai_analysis || null;

        console.log(`🔍 Checked URL: ${url}`);
        console.log(`📌 Threat in dataset? ${isDatasetThreat}`);
        console.log(`🚨 Threat? ${isThreat}`);
        console.log(`📊 Malicious Probability: ${probability}%`);
        if (genaiText) {
          console.log(`🧠 GenAI Analysis: ${genaiText}`);
        }

        if (!isThreat) {
          chrome.action.setIcon({
            path: {
              "16": "icons/safe16.png",
              "48": "icons/safe48.png",
              "128": "icons/safe128.png",
            },
            tabId: tabId,
          });

          chrome.action.setPopup({
            popup: "popup_safe.html",
            tabId: tabId,
          });

          console.log("✅ Safe or unknown site detected, no notification displayed.");
        } else {
          chrome.action.setIcon({
            path: {
              "16": "icons/warning16.png",
              "48": "icons/warning48.png",
              "128": "icons/warning128.png",
            },
            tabId: tabId,
          });

          chrome.action.setPopup({
            popup: "popup.html",
            tabId: tabId,
          });

          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/warning48.png",
            title: "⚠️ Unsafe Website Detected!",
            message: `Potential threat found on:\n${url}`,
            priority: 2,
          });
        }

        chrome.storage.local.set(
          {
            threatData: {
              url: data.url || url,
              message: data.message || "",
              malicious_probability: probability,
              threat: isThreat,
              dataset: isDatasetThreat,
              genai_analysis: genaiText, // ✅ Added for GenAI in popup
            },
          },
          () => {
            if (chrome.runtime.lastError) {
              console.error("❌ Error saving to storage:", chrome.runtime.lastError);
            } else {
              console.log("✅ Threat data saved to storage:", {
                url: data.url || url,
                message: data.message,
                malicious_probability: probability,
                threat: isThreat,
                dataset: isDatasetThreat,
                genai_analysis: genaiText,
              });
            }
          }
        );
      })
      .catch((error) => {
        console.error("❌ Error in threat detection:", error);
      });
  }
});

function isGoogleSearch(url) {
  return url.startsWith("https://www.google.com/search?");
}

async function checkUrlSafety(url) {
  const apiUrl = "https://threats-analysis.onrender.com/check_url";

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      console.error(`⚠️ API error (${response.status}): ${response.statusText}`);
      return { error: `API error (${response.status}): ${response.statusText}` };
    }

    const data = await response.json();
    console.log("📡 API Response:", data);

    if (!("malicious_probability" in data) && !("threat" in data) && !("dataset" in data)) {
      console.warn("⚠️ API response missing expected fields. Marking as safe by default.");
      return {
        url: url,
        malicious_probability: 0,
        threat: false,
        dataset: false,
        message: "No threat found by default"
      };
    }

    return data;

  } catch (error) {
    console.error("❌ Error connecting to the API:", error);
    return { error: "Error connecting to the API" };
  }
}
