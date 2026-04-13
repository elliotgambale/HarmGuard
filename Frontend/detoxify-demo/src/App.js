import React, { useState } from 'react';
import './App.css';

function formatLabel(key) {
  return key
    .split('_')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatValue(value) {
  if (typeof value === 'number') {
    return Number(value).toFixed(3);
  }
  if (Array.isArray(value)) {
    return value.length ? value.join(', ') : 'None';
  }
  if (value && typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return value === null || value === undefined || value === '' ? 'N/A' : String(value);
}

function signalHighlights(signal) {
  const details = signal?.details || {};
  return Object.entries(details).slice(0, 3);
}

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const submit = async e => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError('');

    const fetchUrl = url.match(/^https?:\/\//i) ? url : `https://${url}`;

    try {
      const res = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: fetchUrl }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Unknown error');
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <main className="dashboard">
        <section className="hero-panel">
          <div className="hero-copy">
            <p className="eyebrow">Multi-signal website screening</p>
            <h1>HarmGuard</h1>
            <p className="hero-text">
              Analyze a live page across content, images, scripts, domain reputation,
              and metadata signals.
            </p>
          </div>

          <form className="analyze-form" onSubmit={submit}>
            <label className="field-label" htmlFor="url-input">
              Target URL
            </label>
            <div className="field-row">
              <input
                id="url-input"
                type="text"
                placeholder="example.com or https://example.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                required
                className="url-input"
              />
              <button type="submit" disabled={loading} className="submit-button">
                {loading ? 'Scanning...' : 'Run Analysis'}
              </button>
            </div>
            <p className="helper-text">
              Backend must be running on <code>http://localhost:8000</code>.
            </p>
          </form>

          {error && <div className="error-banner">{error}</div>}
        </section>

        {result && (
          <>
            <section className="summary-grid">
              <article className={`score-card ${result.is_harmful ? 'danger' : 'safe'}`}>
                <div className="score-card-header">
                  <span className="pill">
                    {result.is_harmful ? 'Flagged' : 'Clear'}
                  </span>
                </div>
                <div className="score-value">{Number(result.risk_score).toFixed(3)}</div>
                <h2>Overall Risk Score</h2>
                <p className="score-description">
                  {result.is_harmful
                    ? 'This site crossed the harmful-content threshold.'
                    : 'This site stayed below the harmful-content threshold.'}
                </p>
              </article>

              <article className="summary-card">
                <h3>Primary Reasons</h3>
                <div className="tag-list">
                  {(result.reasons || []).length > 0 ? (
                    result.reasons.map(reason => (
                      <span key={reason} className="reason-tag">
                        {reason}
                      </span>
                    ))
                  ) : (
                    <span className="reason-tag neutral">No signals were flagged</span>
                  )}
                </div>
              </article>

              <article className="summary-card">
                <h3>Signal Weights</h3>
                <div className="weight-list">
                  {Object.entries(result.weights || {}).map(([key, value]) => (
                    <div key={key} className="weight-row">
                      <span>{formatLabel(key)}</span>
                      <strong>{Math.round(Number(value) * 100)}%</strong>
                    </div>
                  ))}
                </div>
              </article>
            </section>

            <section className="signals-section">
              <div className="section-heading">
                <p className="eyebrow">Signal Breakdown</p>
                <h2>What drove the final score</h2>
              </div>

              <div className="signal-grid">
                {Object.entries(result.breakdown || {}).map(([key, signal]) => (
                  <article key={key} className="signal-card">
                    <div className="signal-card-top">
                      <div>
                        <p className="signal-label">{formatLabel(key)}</p>
                        <div className="signal-score">
                          {Number(signal.score || 0).toFixed(3)}
                        </div>
                      </div>
                      <span className={`signal-status ${signal.flagged ? 'flagged' : 'clear'}`}>
                        {signal.flagged ? 'Flagged' : 'Clear'}
                      </span>
                    </div>

                    <div className="meter">
                      <div
                        className={`meter-fill ${signal.flagged ? 'flagged' : 'clear'}`}
                        style={{ width: `${Math.max(6, Number(signal.score || 0) * 100)}%` }}
                      />
                    </div>

                    <div className="detail-list">
                      {signalHighlights(signal).map(([detailKey, detailValue]) => (
                        <div key={detailKey} className="detail-row">
                          <span>{formatLabel(detailKey)}</span>
                          <strong>{formatValue(detailValue)}</strong>
                        </div>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}
