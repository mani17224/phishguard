/**
 * PhishGuard Pro — Background Service Worker
 * Handles URL scanning, badge updates, notifications, and caching.
 */

const API_BASE     = "http://localhost:5050";
const CACHE_TTL_MS = 10 * 60 * 1000;   // 10 minutes
const MAX_CACHE    = 500;

// In-memory LRU cache: url → { result, ts }
const cache = new Map();

// Session stats
let stats = { scanned: 0, phishing: 0, suspicious: 0, safe: 0 };

// ── Settings defaults ────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  apiUrl:              "http://localhost:5050",
  scanEnabled:         true,
  notifyHigh:          true,
  notifyMedium:        false,
  showBadge:           true,
  autoBlockHigh:       false,
  cacheEnabled:        true,
  whitelistedDomains:  [],
};

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get(DEFAULT_SETTINGS, resolve);
  });
}

// ── Cache helpers ────────────────────────────────────────────────
function cacheGet(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    cache.delete(url);
    return null;
  }
  return entry.result;
}

function cacheSet(url, result) {
  if (cache.size >= MAX_CACHE) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
  cache.set(url, { result, ts: Date.now() });
}

// ── Badge update ─────────────────────────────────────────────────
async function setBadge(tabId, tier, settings) {
  if (!settings.showBadge) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const config = {
    HIGH:    { text: "⚠",  color: "#EF4444" },
    MEDIUM:  { text: "?",  color: "#F59E0B" },
    LOW:     { text: "✓",  color: "#10B981" },
    LOADING: { text: "…",  color: "#6366F1" },
    ERROR:   { text: "!",  color: "#6B7280" },
  };
  const { text, color } = config[tier] || config.ERROR;
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// ── Send notification ────────────────────────────────────────────
function notify(result) {
  const icons = { HIGH: "🚨", MEDIUM: "⚠️" };
  chrome.notifications.create({
    type:    "basic",
    iconUrl: "icons/icon48.png",
    title:   `${icons[result.risk_tier] || ""} PhishGuard Pro Alert`,
    message: `${result.verdict} — ${result.probability * 100 | 0}% confidence\n${result.url.slice(0, 80)}`,
    priority: result.risk_tier === "HIGH" ? 2 : 1,
  });
}

// ── Core scan function ───────────────────────────────────────────
async function scanUrl(url, tabId) {
  const settings = await getSettings();

  if (!settings.scanEnabled) return null;

  // Skip internal / extension pages
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")
           || url.startsWith("about:") || url.startsWith("moz-extension://")) {
    return null;
  }

  // Check whitelist
  try {
    const hostname = new URL(url).hostname;
    if (settings.whitelistedDomains.includes(hostname)) {
      await setBadge(tabId, "LOW", settings);
      return null;
    }
  } catch (e) { return null; }

  // Cache check
  if (settings.cacheEnabled) {
    const cached = cacheGet(url);
    if (cached) {
      await updateUI(tabId, cached, settings);
      return cached;
    }
  }

  // Badge: loading
  await setBadge(tabId, "LOADING", settings);

  try {
    const res = await fetch(`${settings.apiUrl}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();

    // Cache
    if (settings.cacheEnabled) cacheSet(url, result);

    // Update stats
    stats.scanned++;
    if      (result.risk_tier === "HIGH")   { stats.phishing++;   }
    else if (result.risk_tier === "MEDIUM") { stats.suspicious++; }
    else                                     { stats.safe++;       }

    await updateUI(tabId, result, settings);

    // Notify on threats
    if (result.risk_tier === "HIGH"   && settings.notifyHigh)   notify(result);
    if (result.risk_tier === "MEDIUM" && settings.notifyMedium) notify(result);

    // Auto-block (if enabled)
    if (result.risk_tier === "HIGH" && settings.autoBlockHigh) {
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}&prob=${result.probability}`)
      });
    }

    return result;
  } catch (err) {
    console.warn("[PhishGuard] Scan failed:", err.message);
    await setBadge(tabId, "ERROR", settings);
    return null;
  }
}

async function updateUI(tabId, result, settings) {
  await setBadge(tabId, result.risk_tier, settings);

  // Store result for popup
  chrome.storage.session.set({
    [`result_${tabId}`]: result,
    [`stats`]: stats,
  });
}

// ── Event listeners ──────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  if (details.transitionType === "auto_subframe") return;
  await scanUrl(details.url, details.tabId);
}, { url: [{ schemes: ["http", "https"] }] });

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url) return;
  const cached = cacheGet(tab.url);
  if (cached) {
    const settings = await getSettings();
    await updateUI(tabId, cached, settings);
  }
});

// Message handler (from popup / content scripts)
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type === "GET_RESULT") {
    chrome.storage.session.get(`result_${msg.tabId}`, (data) => {
      respond({ result: data[`result_${msg.tabId}`] || null, stats });
    });
    return true; // async
  }
  if (msg.type === "SCAN_NOW") {
    scanUrl(msg.url, msg.tabId).then(respond);
    return true;
  }
  if (msg.type === "GET_STATS") {
    respond({ stats });
    return true;
  }
  if (msg.type === "CLEAR_CACHE") {
    cache.clear();
    respond({ ok: true });
    return true;
  }
});
