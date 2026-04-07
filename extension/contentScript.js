(() => {
  if (window.__harmfulWarningInjected) {
    return;
  }
  window.__harmfulWarningInjected = true;

  const OVERLAY_ID = '__site_safety_monitor_overlay__';

  function getMountNode() {
    return document.body || document.documentElement;
  }

  function buildReasonText(reasons) {
    return reasons.length > 0 ? reasons.join(', ') : 'multiple risk signals';
  }

  function attachDismissHandler(overlay) {
    const dismissButton = overlay.querySelector('#dismiss-warning');
    if (!dismissButton) {
      return;
    }

    dismissButton.addEventListener('click', () => overlay.remove());
  }

  function showOverlay(riskScore, threshold, reasons) {
    if (document.getElementById(OVERLAY_ID)) {
      return;
    }

    const mountNode = getMountNode();
    if (!mountNode) {
      window.addEventListener(
        'DOMContentLoaded',
        () => showOverlay(riskScore, threshold, reasons),
        { once: true }
      );
      return;
    }

    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    Object.assign(overlay.style, {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(8, 9, 12, 0.88)',
      color: 'white',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: '2147483647',
      padding: '2rem',
      textAlign: 'center',
      fontFamily: 'Arial, sans-serif',
    });

    overlay.innerHTML = `
      <div style="max-width: 680px; background: #13161c; border: 1px solid rgba(255,255,255,0.12); border-radius: 24px; padding: 32px; box-shadow: 0 24px 60px rgba(0,0,0,0.35);">
        <div style="display:inline-flex; padding:8px 12px; border-radius:999px; background:rgba(255,123,84,0.18); color:#ffb49b; font-size:12px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase;">
          Site flagged
        </div>
        <h1 style="margin:18px 0 12px; font-size:40px; line-height:1.05;">This site may be harmful</h1>
        <p style="margin:0; font-size:18px; line-height:1.6; color:rgba(255,255,255,0.82);">
          Risk score: ${riskScore.toFixed(3)} (threshold ${threshold.toFixed(2)})
        </p>
        <p style="margin:14px 0 0; font-size:16px; line-height:1.6; color:rgba(255,255,255,0.72);">
          Reasons: ${buildReasonText(reasons)}
        </p>
        <button id="dismiss-warning" style="margin-top:24px; padding:12px 18px; font-size:15px; font-weight:700; border:0; border-radius:12px; background:#f6f1ea; color:#111318; cursor:pointer;">
          Dismiss and continue
        </button>
      </div>
    `;

    attachDismissHandler(overlay);
    mountNode.appendChild(overlay);
  }

  (async () => {
    const url = window.location.href;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_URL',
        url,
      });

      if (!response?.ok) {
        console.error('Site Safety Monitor analyze failed:', response?.error);
        return;
      }

      const { is_harmful, risk_score, threshold, reasons = [] } = response.data;
      if (!is_harmful) {
        return;
      }

      showOverlay(risk_score, threshold, reasons);
    } catch (err) {
      console.error('Site Safety Monitor error:', err);
    }
  })();
})();
