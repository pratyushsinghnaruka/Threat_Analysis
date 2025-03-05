// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "checkPage") {
      const scripts = document.querySelectorAll("script");
      let isMalicious = false;
  
      scripts.forEach((script) => {
        if (script.src.includes("malicious-domain")) {
          isMalicious = true;
        }
      });
  
      sendResponse({ isMalicious });
    }
  });