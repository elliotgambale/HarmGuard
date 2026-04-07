(() => {
  if (window.__harmfulWarningInjected) {
    return;
  }
  window.__harmfulWarningInjected = true;

  (async () => {
    const url = window.location.href;

    try {
      const resp = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!resp.ok) return;

      const { is_harmful, risk_score, threshold, reasons = [] } = await resp.json();
      if (!is_harmful) return;

      const overlay = document.createElement('div');
      Object.assign(overlay.style, {
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0,0,0,0.85)',
        color: 'white',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        zIndex: 999999,
        padding: '2rem',
        textAlign: 'center',
      });

      const reasonText = reasons.length > 0 ? reasons.join(', ') : 'multiple risk signals';
      overlay.innerHTML = `
        <h1>⚠️ This site may be harmful</h1>
        <p>Risk score: ${risk_score.toFixed(3)} (threshold ${threshold})</p>
        <p>Reasons: ${reasonText}</p>
        <button id="dismiss-warning" style="margin-top:1rem;padding:0.5rem 1rem;font-size:1rem;">
          Dismiss and continue
        </button>
      `;
      document.body.appendChild(overlay);

      document
        .getElementById('dismiss-warning')
        .addEventListener('click', () => overlay.remove());
    } catch (err) {
      console.error('Site Safety Monitor error:', err);
    }
  })();
})();
