/**
 * PhishGuard Pro — Content Script
 * Injected into every page. Displays an in-page warning banner
 * for HIGH-risk URLs. Lightweight and non-blocking.
 */

(function () {
  "use strict";

  let bannerInjected = false;

  // Listen for scan results from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_WARNING" && msg.result) {
      showBanner(msg.result);
    }
    if (msg.type === "HIDE_WARNING") {
      removeBanner();
    }
  });

  function showBanner(result) {
    if (bannerInjected) return;
    if (result.risk_tier !== "HIGH") return;

    bannerInjected = true;
    const prob = (result.probability * 100).toFixed(1);

    const banner = document.createElement("div");
    banner.id = "phishguard-banner";
    banner.innerHTML = `
      <div style="
        position:fixed; top:0; left:0; right:0; z-index:2147483647;
        background:linear-gradient(135deg,#7f1d1d,#991b1b);
        border-bottom:2px solid #ef4444;
        padding:10px 20px;
        display:flex; align-items:center; gap:14px;
        font-family:'Segoe UI',Arial,sans-serif;
        font-size:13px; color:white;
        box-shadow:0 4px 24px rgba(239,68,68,0.4);
        animation: slideDown 0.3s ease;
      ">
        <style>
          @keyframes slideDown { from { transform:translateY(-100%); opacity:0; } to { transform:translateY(0); opacity:1; } }
        </style>
        <span style="font-size:22px;flex-shrink:0">⚠</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;font-size:14px">
            PhishGuard Pro — Phishing Detected (${prob}% confidence)
          </div>
          <div style="font-size:11px;opacity:0.8;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${result.url}
          </div>
          <div style="font-size:11px;opacity:0.7;margin-top:2px">
            ${(result.signals || []).filter(s=>s.type==='danger').map(s=>s.msg).slice(0,2).join(' · ')}
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-shrink:0">
          <button id="pg-go-back" style="
            background:rgba(255,255,255,0.15); border:1px solid rgba(255,255,255,0.3);
            color:white; padding:6px 14px; border-radius:6px; cursor:pointer;
            font-size:12px; font-weight:600;
          ">← Go Back</button>
          <button id="pg-proceed" style="
            background:transparent; border:1px solid rgba(255,255,255,0.3);
            color:rgba(255,255,255,0.6); padding:6px 12px; border-radius:6px;
            cursor:pointer; font-size:11px;
          ">Proceed anyway</button>
          <button id="pg-close" style="
            background:transparent; border:none; color:rgba(255,255,255,0.5);
            cursor:pointer; font-size:18px; padding:0 4px; line-height:1;
          ">✕</button>
        </div>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("pg-go-back")?.addEventListener("click", () => {
      history.back();
    });
    document.getElementById("pg-proceed")?.addEventListener("click", () => {
      removeBanner();
    });
    document.getElementById("pg-close")?.addEventListener("click", () => {
      removeBanner();
    });
  }

  function removeBanner() {
    const b = document.getElementById("phishguard-banner");
    if (b) { b.remove(); bannerInjected = false; }
  }
})();
