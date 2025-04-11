chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const url = changeInfo.url;
    console.log("🔄 URL changed:", url);

    if (isGoogleSearch(url)) {
      markAsSafe(tabId, url, "Google Search is always safe.");
      return;
    }

    checkUrlSafety(url).then((data) => {
      if (data.error) {
        console.error("⚠ Threat detection failed:", data.error);
        return;
      }

      const probability = typeof data.malicious_probability === "number" ? data.malicious_probability : 0;
      const isDatasetThreat = data.dataset === true;
      const isThreat = isDatasetThreat || data.threat === true || probability > 50;

      let genaiText = data.genai_analysis || "";

      // 🧠 Fix vague or contradictory GenAI outputs
      if (genaiText.toLowerCase().includes("false") && probability >= 0.9) {
        genaiText = "⚠ Likely malicious (based on ML and API results)";
      }

      const weakGenAI = genaiText.toLowerCase().includes("appears to be a legitimate") ||
                        genaiText.toLowerCase().includes("always be cautious") ||
                        genaiText.length < 100;

      if (probability >= 0.95 && weakGenAI) {
        genaiText =
          "⚠ This website is flagged as malicious by our systems.\n\n" +
          "GenAI was unable to provide a reliable analysis, but our ML and API responses strongly indicate this site is unsafe.\n\n" +
          "Malicious Probability: " + probability.toFixed(2) + "%";
      }

      // 🧠 Logging
      console.log("🔍 Checked URL:", url);
      console.log("📌 Threat in dataset?", isDatasetThreat);
      console.log("🚨 Threat?", isThreat);
      console.log("📊 Malicious Probability:", probability + "%");
      if (genaiText) console.log("🧠 GenAI Analysis:", genaiText);

      // 🔔 UI + Icon updates
      if (!isThreat) {
        markAsSafe(tabId, url, data.message || "No known threats detected.");
      } else {
        markAsThreat(tabId, url);
      }

      // 💾 Save threat data to local storage
      chrome.storage.local.set({
        threatData: {
          url: data.url || url,
          message: data.message || "",
          malicious_probability: probability,
          threat: isThreat,
          dataset: isDatasetThreat,
          genai_analysis: genaiText,
        },
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("❌ Error saving to storage:", chrome.runtime.lastError);
        } else {
          console.log("✅ Threat data saved.");
        }
      });

    }).catch((error) => {
      console.error("❌ Error in threat detection:", error);
    });
  }
});

function isGoogleSearch(url) {
  return url.startsWith("https://www.google.com/search?");
}

function markAsSafe(tabId, url, message) {
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
      message: message,
      malicious_probability: 0,
      threat: false,
      dataset: false,
    },
  });

  console.log("✅ Safe site set with popup_safe.");
}

function markAsThreat(tabId, url) {
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
    title: "⚠ Unsafe Website Detected!",
    message: `Potential threat found on:\n${url}`,
    priority: 2,
  });

  console.log("🚨 Threat detected, popup and icon updated.");
}

async function checkUrlSafety(url) {
  const apiUrl = "https://threats-analysis.onrender.com/analyze";

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      const errorMsg = `API error (${response.status}): ${response.statusText}`;
      console.error("⚠", errorMsg);
      return { error: errorMsg };
    }

    const data = await response.json();
    console.log("📡 API Response:", data);

    // Validate expected fields
    if (!("malicious_probability" in data) && !("threat" in data) && !("dataset" in data)) {
      console.warn("⚠ API response missing fields. Marking as safe.");
      return {
        url: url,
        malicious_probability: 0,
        threat: false,
        dataset: false,
        message: "No threat found by default",
      };
    }

    return data;
  } catch (error) {
    console.error("❌ API fetch failed:", error);
    return { error: "Error connecting to the API" };
  }
}
