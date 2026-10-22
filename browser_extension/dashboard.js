// CyberSentinel Browser Extension Dashboard Controller (Manifest V3 CSP Compliant)

let cachedPackets = [];
let cachedAlerts = [];
let cachedQuarantined = [];

document.addEventListener('DOMContentLoaded', () => {
  // Event listeners (CSP compliant - no inline onclick)
  const btnExport = document.getElementById('btn-export-audit');
  if (btnExport) {
    btnExport.addEventListener('click', exportAuditReport);
  }

  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderStreamTable();
    });
  }

  // Event delegation for quarantine actions
  document.getElementById('incidents-list').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="quarantine"]');
    if (btn && btn.dataset.domain) {
      quarantineDomain(btn.dataset.domain);
    }
  });

  document.getElementById('quarantine-tags').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="unblock"]');
    if (btn && btn.dataset.domain) {
      unblockDomain(btn.dataset.domain);
    }
  });

  fetchExtensionData();
  setInterval(fetchExtensionData, 1500);
});

function fetchExtensionData() {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ action: 'GET_DATA' }, (response) => {
      if (!response) return;
      cachedPackets = response.recentPackets || [];
      cachedAlerts = response.alerts || [];
      cachedQuarantined = response.quarantinedDomains || [];
      updateDashboardUI(response.totalRequests);
    });
  } else {
    simulateBrowserFeed();
  }
}

function updateDashboardUI(totalRequests) {
  document.getElementById('stat-total-reqs').textContent = (totalRequests || cachedPackets.length).toLocaleString();
  document.getElementById('stat-quarantined').textContent = cachedQuarantined.length;
  document.getElementById('stat-alerts').textContent = cachedAlerts.length;
  document.getElementById('alerts-count-badge').textContent = `${cachedAlerts.length} ALERTS`;

  renderQuarantineTags();
  renderAlerts();
  renderStreamTable();
}

function renderQuarantineTags() {
  const container = document.getElementById('quarantine-tags');
  if (cachedQuarantined.length === 0) {
    container.innerHTML = '<span style="color: #64748b; font-style: italic;">No domains quarantined yet. Click "Quarantine" on any alert below to drop connection.</span>';
    return;
  }

  container.innerHTML = cachedQuarantined.map(domain => `
    <span class="quarantine-chip">
      <span>🚫 ${domain}</span>
      <button class="btn-unblock" data-action="unblock" data-domain="${domain}" title="Release / Unblock">✕</button>
    </span>
  `).join('');
}

function renderAlerts() {
  const container = document.getElementById('incidents-list');
  if (cachedAlerts.length === 0) {
    container.innerHTML = '<div style="padding: 12px; background: rgba(9, 13, 24, 0.4); border: 1px solid #1e293b; border-radius: 8px; text-align: center; color: #64748b;">✔ Clean: Zero security anomalies registered in active session.</div>';
    return;
  }

  container.innerHTML = cachedAlerts.map(a => {
    const isBlocked = cachedQuarantined.includes(a.host);
    const badgeClass = a.severity === 'HIGH' ? 'badge-rose' : 'badge-amber';

    return `
      <div class="incident-item">
        <div class="incident-info">
          <div class="incident-header">
            <span class="badge ${badgeClass}">${a.severity}</span>
            <span class="incident-title">${a.title}</span>
            <span class="incident-time">${a.time}</span>
          </div>
          <div class="incident-host">${a.host}</div>
          <div class="incident-desc">${a.desc}</div>
        </div>

        <div>
          ${isBlocked 
            ? '<span class="badge badge-rose" style="padding: 4px 8px;">QUARANTINED</span>' 
            : `<button class="btn btn-danger" data-action="quarantine" data-domain="${a.host}">
                 ⛔ Quarantine Host
               </button>`
          }
        </div>
      </div>
    `;
  }).join('');
}

function renderStreamTable() {
  const searchInput = document.getElementById('search-input');
  const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
  const tbody = document.getElementById('stream-tbody');

  const filtered = cachedPackets.filter(p => 
    searchTerm === '' || (p.hostname && p.hostname.toLowerCase().includes(searchTerm)) || (p.url && p.url.toLowerCase().includes(searchTerm))
  );

  tbody.innerHTML = filtered.slice(0, 40).map(p => {
    const isBlocked = cachedQuarantined.includes(p.hostname);
    const rowClass = isBlocked ? 'blocked-row' : '';
    const protoBadge = p.protocol === 'HTTPS' ? 'badge-cyan' : 'badge-amber';

    return `
      <tr class="${rowClass}">
        <td style="color: #64748b;">${p.timestamp}</td>
        <td><span class="badge ${protoBadge}">${p.protocol}</span></td>
        <td style="font-weight: 700; color: #cbd5e1;">${p.method}</td>
        <td style="font-weight: 600; ${isBlocked ? 'text-decoration: line-through; color: #f43f5e;' : 'color: #f8fafc;'}">${p.hostname}</td>
        <td style="color: #94a3b8; text-transform: uppercase;">${p.type || 'fetch'}</td>
        <td class="url-cell" title="${p.url}">${p.url}</td>
      </tr>
    `;
  }).join('');
}

function quarantineDomain(domain) {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ action: 'QUARANTINE_DOMAIN', domain: domain }, () => fetchExtensionData());
  } else {
    if (!cachedQuarantined.includes(domain)) {
      cachedQuarantined.push(domain);
      updateDashboardUI();
    }
  }
}

function unblockDomain(domain) {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ action: 'UNBLOCK_DOMAIN', domain: domain }, () => fetchExtensionData());
  } else {
    cachedQuarantined = cachedQuarantined.filter(d => d !== domain);
    updateDashboardUI();
  }
}

function exportAuditReport() {
  const text = `
================================================================================
          CYBER SENTINEL - BROWSER NETWORK DEFENSE AUDIT REPORT
================================================================================
Generated: ${new Date().toLocaleString()}
Total Intercepted Browser Requests: ${cachedPackets.length}
Active Quarantined Domains (${cachedQuarantined.length}):
${cachedQuarantined.length > 0 ? cachedQuarantined.map(d => ` - 🚫 ${d}`).join('\n') : ' (None)'}

Security Alerts (${cachedAlerts.length}):
${cachedAlerts.map(a => `[${a.severity}] ${a.time} - Host: ${a.host}
  Threat: ${a.title}
  Detail: ${a.desc}`).join('\n\n')}
================================================================================
`;
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `browser_network_audit_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// Fallback dummy feed if opened as static local file
function simulateBrowserFeed() {
  if (cachedPackets.length === 0) {
    const domains = [
      { host: "github.com", url: "https://github.com/api/v3/user", type: "xmlhttprequest", proto: "HTTPS" },
      { host: "google-analytics.com", url: "https://google-analytics.com/g/collect?v=2", type: "ping", proto: "HTTPS" },
      { host: "doubleclick.net", url: "https://ad.doubleclick.net/ddm/ad/N1234", type: "sub_frame", proto: "HTTPS" },
      { host: "insecure-cdn.xyz", url: "http://insecure-cdn.xyz/tracker.js", type: "script", proto: "HTTP" },
      { host: "cdnjs.cloudflare.com", url: "https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.js", type: "script", proto: "HTTPS" }
    ];

    domains.forEach((d, i) => {
      cachedPackets.unshift({
        id: i + 1,
        timestamp: new Date().toLocaleTimeString(),
        url: d.url,
        hostname: d.host,
        method: "GET",
        type: d.type,
        protocol: d.proto
      });
    });

    cachedAlerts.push({
      severity: "LOW",
      title: "Telemetry Surveillance Beacon",
      host: "google-analytics.com",
      desc: "Cross-site background tracking request intercepted",
      time: new Date().toLocaleTimeString()
    });

    cachedAlerts.push({
      severity: "MEDIUM",
      title: "Insecure Cleartext HTTP Transport",
      host: "insecure-cdn.xyz",
      desc: "Script asset loaded over plaintext unencrypted HTTP",
      time: new Date().toLocaleTimeString()
    });

    updateDashboardUI(28);
  }
}
