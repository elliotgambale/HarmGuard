chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'ANALYZE_URL' || !message.url) {
    return false;
  }

  (async () => {
    try {
      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: message.url }),
      });

      if (!response.ok) {
        sendResponse({
          ok: false,
          error: `Analyze request failed with status ${response.status}`,
        });
        return;
      }

      const data = await response.json();
      sendResponse({ ok: true, data });
    } catch (error) {
      sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  })();

  return true;
});
