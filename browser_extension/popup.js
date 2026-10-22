// CyberSentinel Popup Controller (Manifest V3 CSP Compliant)

document.addEventListener('DOMContentLoaded', () => {
  const btnDashboard = document.getElementById('btn-open-dashboard');
  if (btnDashboard) {
    btnDashboard.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    });
  }

  const btnClear = document.getElementById('btn-clear-alerts');
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'CLEAR_ALERTS' }, () => {
        refreshData();
      });
    });
  }

  // Event delegation for quarantine buttons (CSP compliant)
  document.getElementById('alerts-container').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="quarantine"]');
    if (btn && btn.dataset.domain) {
      chrome.runtime.sendMessage({ action: 'QUARANTINE_DOMAIN', domain: btn.dataset.domain }, () => {
        refreshData();
      });
    }
  });

  refreshData();
  setInterval(refreshData, 1500);
});

function refreshData() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;

  chrome.runtime.sendMessage({ action: 'GET_DATA' }, (response) => {
    if (!response) return;

    document.getElementById('stat-requests').textContent = (response.totalRequests || 0).toLocaleString();
    document.getElementById('stat-threats').textContent = (response.alerts || []).length;
    document.getElementById('quarantined-badge').textContent = `${(response.quarantinedDomains || []).length} blocked`;

    // Render Alerts
    const alertsContainer = document.getElementById('alerts-container');
    const alerts = response.alerts || [];
    const quarantined = response.quarantinedDomains || [];

    if (alerts.length === 0) {
      alertsContainer.innerHTML = `
        <div style="padding: 8px; background: rgba(9, 13, 24, 0.4); border: 1px solid #1e293b; border-radius: 6px; text-align: center; color: #64748b; font-size: 10px;">
          ✔ Clean: No security anomalies detected on active session.
        </div>
      `;
    } else {
      alertsContainer.innerHTML = alerts.slice(0, 5).map(a => {
        const isBlocked = quarantined.includes(a.host);
        const badgeColor = a.severity === 'HIGH' ? 'color: #f43f5e; border-color: rgba(244, 63, 94, 0.4); background: rgba(244, 63, 94, 0.15);' : 'color: #f59e0b; border-color: rgba(245, 158, 11, 0.4); background: rgba(245, 158, 11, 0.15);';
        return `
          <div style="padding: 8px; background: #090d18; border: 1px solid #1e293b; border-radius: 6px; display: flex; flex-direction: column; gap: 4px;">
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 9px;">
              <span style="font-weight: 700; padding: 1px 4px; border-radius: 3px; border: 1px solid; ${badgeColor}">[${a.severity}] ${a.title}</span>
              <span style="color: #64748b;">${a.time}</span>
            </div>
            <div style="font-size: 11px; font-weight: 600; color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${a.host}</div>
            <div style="display: flex; align-items: center; justify-content: space-between; padding-top: 2px;">
              <span style="font-size: 9px; color: #94a3b8;">${a.desc}</span>
              ${isBlocked 
                ? '<span style="font-size: 9px; color: #f43f5e; font-weight: 700;">QUARANTINED</span>'
                : `<button class="btn btn-danger" style="padding: 2px 6px; font-size: 9px;" data-action="quarantine" data-domain="${a.host}">Quarantine</button>`
              }
            </div>
          </div>
        `;
      }).join('');
    }

    // Render Packets
    const packetsContainer = document.getElementById('packets-container');
    const recentPackets = response.recentPackets || [];

    packetsContainer.innerHTML = recentPackets.slice(0, 15).map(p => {
      const isBlocked = quarantined.includes(p.hostname);
      const protoColor = p.protocol === 'HTTPS' ? 'background: rgba(6, 182, 212, 0.15); color: #06b6d4;' : 'background: rgba(245, 158, 11, 0.15); color: #f59e0b;';
      const borderStyle = isBlocked ? 'border-color: rgba(244, 63, 94, 0.4); background: rgba(244, 63, 94, 0.1);' : 'border-color: #1e293b; background: #090d18;';

      return `
        <div style="padding: 6px 8px; border-radius: 6px; border: 1px solid; display: flex; align-items: center; justify-content: space-between; gap: 8px; ${borderStyle}">
          <span style="padding: 1px 4px; border-radius: 3px; font-size: 8px; font-weight: 700; ${protoColor}">${p.protocol}</span>
          <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; ${isBlocked ? 'text-decoration: line-through; color: #f43f5e;' : 'color: #cbd5e1;'}">${p.hostname}</span>
          <span style="font-size: 9px; color: #64748b;">${p.type || p.method}</span>
        </div>
      `;
    }).join('');
  });
}
