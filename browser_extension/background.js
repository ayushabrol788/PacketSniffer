// CyberSentinel Background Service Worker (Manifest V3)
// Live Browser Packet & Network Request Interceptor

const STATE = {
  totalRequests: 0,
  totalBytes: 0,
  quarantinedDomains: new Set(),
  recentPackets: [],
  alerts: [],
  domainFrequency: {},
  startTime: Date.now()
};

// Known Tracking & Telemetry Patterns
const TRACKER_PATTERNS = [
  "doubleclick.net", "google-analytics.com", "analytics.google.com",
  "facebook.net", "adnxs.com", "scorecardresearch.com",
  "hotjar.com", "criteo.com", "taboola.com", "outbrain.com"
];

// Suspicious High-Risk TLDs
const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".buzz", ".work", ".stream"];

// Intercept Live Web Requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    STATE.totalRequests++;

    const urlObj = new URL(details.url);
    const hostname = urlObj.hostname;
    const protocol = urlObj.protocol.replace(':', '').toUpperCase();
    const port = urlObj.port || (protocol === 'HTTPS' ? '443' : '80');
    const now = new Date().toLocaleTimeString();

    // Check if domain is currently in quarantine
    const isQuarantined = STATE.quarantinedDomains.has(hostname);

    const packet = {
      id: STATE.totalRequests,
      timestamp: now,
      url: details.url,
      hostname: hostname,
      method: details.method || 'GET',
      type: details.type,
      protocol: protocol,
      port: port,
      isQuarantined: isQuarantined
    };

    STATE.recentPackets.unshift(packet);
    if (STATE.recentPackets.length > 200) STATE.recentPackets.pop();

    // Track request frequency for burst / DoS detection
    const currSec = Math.floor(Date.now() / 3000);
    const domainKey = `${hostname}_${currSec}`;
    STATE.domainFrequency[domainKey] = (STATE.domainFrequency[domainKey] || 0) + 1;

    // Rule 1: High Burst Frequency (Beaconing / Flooding)
    if (STATE.domainFrequency[domainKey] > 35) {
      flagAlert("HIGH", "High-Frequency Beaconing Anomaly", hostname, 
                `Domain issued >35 requests within a 3-second window (${details.type})`,
                `Consider adding ${hostname} to Quarantine ACL`);
    }

    // Rule 2: Insecure Cleartext Protocol (HTTP)
    if (urlObj.protocol === 'http:' && !hostname.includes('localhost') && !hostname.includes('127.0.0.1')) {
      flagAlert("MEDIUM", "Cleartext Insecure HTTP Transport", hostname,
                `Data transmitted in plaintext over HTTP to ${hostname}`,
                `Upgrade site to HTTPS or block non-SSL connections`);
    }

    // Rule 3: Tracker & Ad Telemetry Detection
    if (TRACKER_PATTERNS.some(p => hostname.includes(p))) {
      flagAlert("LOW", "Telemetry / Surveillance Tracker", hostname,
                `Background telemetry beacon detected from known tracker ${hostname}`,
                `1-Click Quarantine domain to prevent cross-site profiling`);
    }

    // Rule 4: Suspicious Non-Standard Ports
    if (port && port !== '80' && port !== '443' && port !== '8080') {
      flagAlert("MEDIUM", "Non-Standard Port Connection", hostname,
                `Outbound browser request targeted unusual port :${port}`,
                `Verify legitimacy of port :${port} service`);
    }

    // Persist latest state
    syncStorage();
  },
  { urls: ["<all_urls>"] }
);

function flagAlert(severity, title, host, desc, remediation) {
  // Avoid duplicate alerts for the same host within 10s
  const exists = STATE.alerts.some(a => a.host === host && (Date.now() - a.timestampMs) < 10000);
  if (exists) return;

  const alert = {
    id: Date.now() + Math.random(),
    severity: severity,
    title: title,
    host: host,
    desc: desc,
    remediation: remediation,
    time: new Date().toLocaleTimeString(),
    timestampMs: Date.now()
  };

  STATE.alerts.unshift(alert);
  if (STATE.alerts.length > 50) STATE.alerts.pop();

  // Set badge on extension icon
  chrome.action.setBadgeText({ text: STATE.alerts.length.toString() });
  chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
}

function syncStorage() {
  chrome.storage.local.set({
    totalRequests: STATE.totalRequests,
    recentPackets: STATE.recentPackets.slice(0, 50),
    alerts: STATE.alerts,
    quarantinedDomains: Array.from(STATE.quarantinedDomains)
  });
}

// Listen for messages from popup or dashboard
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_DATA') {
    sendResponse({
      totalRequests: STATE.totalRequests,
      recentPackets: STATE.recentPackets,
      alerts: STATE.alerts,
      quarantinedDomains: Array.from(STATE.quarantinedDomains)
    });
  } else if (request.action === 'QUARANTINE_DOMAIN') {
    STATE.quarantinedDomains.add(request.domain);
    syncStorage();
    sendResponse({ success: true, quarantined: Array.from(STATE.quarantinedDomains) });
  } else if (request.action === 'UNBLOCK_DOMAIN') {
    STATE.quarantinedDomains.delete(request.domain);
    syncStorage();
    sendResponse({ success: true, quarantined: Array.from(STATE.quarantinedDomains) });
  } else if (request.action === 'CLEAR_ALERTS') {
    STATE.alerts = [];
    chrome.action.setBadgeText({ text: '' });
    syncStorage();
    sendResponse({ success: true });
  }
  return true;
});
