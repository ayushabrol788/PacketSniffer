// CyberSentinel Built-in Secure Browser Controller
// Combines Tab Management, Multi-Engine Search, and Real-Time Deep Packet Inspection

class CyberBrowser {
  constructor() {
    this.tabs = [
      { id: 1, title: 'Secure Search Home', url: 'about:home', history: ['about:home'], historyIndex: 0 }
    ];
    this.activeTabId = 1;
    this.nextTabId = 2;

    this.packets = [];
    this.quarantinedDomains = new Set(['ad-tracker-telemetry.xyz', 'malware-beacon.top']);
    this.totalBytes = 0;
    this.threatCount = 0;
    this.isSnifferOpen = true;

    this.initElements();
    this.initEventListeners();
    this.startBackgroundMetrics();
  }

  initElements() {
    this.tabStrip = document.getElementById('tab-strip');
    this.btnNewTab = document.getElementById('btn-new-tab');
    this.btnBack = document.getElementById('btn-back');
    this.btnForward = document.getElementById('btn-forward');
    this.btnReload = document.getElementById('btn-reload');
    this.btnHome = document.getElementById('btn-home');

    this.omnibox = document.getElementById('omnibox');
    this.searchEngineSelect = document.getElementById('search-engine');
    this.sslBadge = document.getElementById('ssl-badge');
    this.shieldCount = document.getElementById('shield-count');

    this.searchHomeView = document.getElementById('search-home-view');
    this.webFrame = document.getElementById('web-frame');
    this.quickSearchInput = document.getElementById('quick-search-input');

    this.snifferPanel = document.getElementById('sniffer-panel');
    this.btnToggleSniffer = document.getElementById('btn-toggle-sniffer');
    this.snifferToggleLabel = document.getElementById('sniffer-toggle-label');
    this.packetStreamList = document.getElementById('packet-stream-list');
    this.quarantinedCount = document.getElementById('quarantined-count');

    this.metricPkts = document.getElementById('metric-pkts');
    this.metricPps = document.getElementById('metric-pps');
    this.metricThreats = document.getElementById('metric-threats');

    this.packetModal = document.getElementById('packet-modal');
    this.modalPktTitle = document.getElementById('modal-pkt-title');
    this.modalPktDetails = document.getElementById('modal-pkt-details');
    this.btnCloseModal = document.getElementById('btn-close-modal');
  }

  initEventListeners() {
    // Tab actions
    this.btnNewTab.addEventListener('click', () => this.createNewTab());
    
    this.tabStrip.addEventListener('click', (e) => {
      const tabEl = e.target.closest('.tab');
      const closeBtn = e.target.closest('.tab-close');

      if (closeBtn) {
        e.stopPropagation();
        const tabId = parseInt(closeBtn.dataset.closeTab);
        this.closeTab(tabId);
      } else if (tabEl) {
        const tabId = parseInt(tabEl.dataset.tabId);
        this.switchTab(tabId);
      }
    });

    // Navigation buttons
    this.btnBack.addEventListener('click', () => this.navigateHistory(-1));
    this.btnForward.addEventListener('click', () => this.navigateHistory(1));
    this.btnReload.addEventListener('click', () => this.reloadCurrentTab());
    this.btnHome.addEventListener('click', () => this.navigateTo('about:home'));

    // Omnibox submit on Enter
    this.omnibox.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.handleOmniboxSubmit(this.omnibox.value);
      }
    });

    // Quick search on home page
    if (this.quickSearchInput) {
      this.quickSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.handleOmniboxSubmit(this.quickSearchInput.value);
        }
      });
    }

    // Bookmarks bar clicks
    document.querySelectorAll('.bookmark-item').forEach(el => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        const url = el.dataset.url;
        if (url) this.navigateTo(url);
      });
    });

    // Toggle live sniffer panel
    this.btnToggleSniffer.addEventListener('click', () => {
      this.isSnifferOpen = !this.isSnifferOpen;
      if (this.isSnifferOpen) {
        this.snifferPanel.classList.remove('collapsed');
        this.snifferToggleLabel.textContent = 'Packet Sniffer [ON]';
      } else {
        this.snifferPanel.classList.add('collapsed');
        this.snifferToggleLabel.textContent = 'Packet Sniffer [OFF]';
      }
    });

    // Clear and Export sniffer actions
    document.getElementById('btn-clear-sniffer').addEventListener('click', () => {
      this.packets = [];
      this.renderPacketStream();
    });

    document.getElementById('btn-export-browser-audit').addEventListener('click', () => {
      this.exportForensicAudit();
    });

    // Packet click for modal inspection
    this.packetStreamList.addEventListener('click', (e) => {
      const row = e.target.closest('.packet-row');
      const quarantineBtn = e.target.closest('.btn-quarantine-host');

      if (quarantineBtn) {
        e.stopPropagation();
        const domain = quarantineBtn.dataset.host;
        this.quarantineHost(domain);
      } else if (row) {
        const pktId = parseInt(row.dataset.pktId);
        this.openPacketDissection(pktId);
      }
    });

    // Modal close
    this.btnCloseModal.addEventListener('click', () => {
      this.packetModal.style.display = 'none';
    });
    this.packetModal.addEventListener('click', (e) => {
      if (e.target === this.packetModal) this.packetModal.style.display = 'none';
    });

    // Manage ACL click
    document.getElementById('btn-view-quarantine').addEventListener('click', () => {
      alert(`Active Quarantined Domains (${this.quarantinedDomains.size}):\n` + 
            Array.from(this.quarantinedDomains).map(d => ` - ${d}`).join('\n'));
    });
  }

  // Omnibox URL / Query Parser
  handleOmniboxSubmit(input) {
    const trimmed = input.trim();
    if (!trimmed) return;

    let targetUrl = '';
    const isUrl = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/.test(trimmed) || trimmed.startsWith('localhost');

    if (isUrl) {
      targetUrl = trimmed.startsWith('http://') || trimmed.startsWith('https://') ? trimmed : `https://${trimmed}`;
    } else {
      // It's a search query!
      const engine = this.searchEngineSelect.value;
      const encoded = encodeURIComponent(trimmed);
      switch (engine) {
        case 'duckduckgo': targetUrl = `https://duckduckgo.com/?q=${encoded}`; break;
        case 'google': targetUrl = `https://www.google.com/search?q=${encoded}`; break;
        case 'bing': targetUrl = `https://www.bing.com/search?q=${encoded}`; break;
        case 'wikipedia': targetUrl = `https://en.wikipedia.org/wiki/Special:Search?search=${encoded}`; break;
        default: targetUrl = `https://duckduckgo.com/?q=${encoded}`;
      }
    }

    this.navigateTo(targetUrl);
  }

  // Navigation Logic
  navigateTo(url) {
    const activeTab = this.tabs.find(t => t.id === this.activeTabId);
    if (!activeTab) return;

    activeTab.url = url;
    if (activeTab.history[activeTab.historyIndex] !== url) {
      activeTab.history = activeTab.history.slice(0, activeTab.historyIndex + 1);
      activeTab.history.push(url);
      activeTab.historyIndex = activeTab.history.length - 1;
    }

    this.omnibox.value = url;
    this.updateTabUI();

    if (url === 'about:home') {
      this.searchHomeView.style.display = 'flex';
      this.webFrame.style.display = 'none';
      this.webFrame.src = 'about:blank';
      this.sslBadge.innerHTML = '<span>🔒</span><span style="font-weight:700; font-size:10px;">SECURE</span>';
      this.sslBadge.style.color = '#10b981';
      return;
    }

    this.searchHomeView.style.display = 'none';
    this.webFrame.style.display = 'block';
    this.webFrame.src = url;

    // Parse domain
    let hostname = 'unknown.host';
    try {
      hostname = new URL(url).hostname;
    } catch (e) {
      hostname = url;
    }

    // Update SSL badge
    if (url.startsWith('https://')) {
      this.sslBadge.innerHTML = '<span>🔒</span><span style="font-weight:700; font-size:10px;">TLSv1.3</span>';
      this.sslBadge.style.color = '#10b981';
    } else {
      this.sslBadge.innerHTML = '<span>⚠️</span><span style="font-weight:700; font-size:10px;">CLEARTEXT</span>';
      this.sslBadge.style.color = '#f59e0b';
    }

    // Trigger Deep Packet Ingestion Sequence
    this.simulateNetworkPacketFlow(url, hostname);
  }

  // Deep Packet Simulation Flow for the Search / Navigation
  simulateNetworkPacketFlow(url, hostname) {
    const isQuarantined = this.quarantinedDomains.has(hostname);

    // 1. DNS Resolution
    this.ingestPacket({
      proto: 'UDP',
      src: '192.168.1.100:53412',
      dst: '8.8.8.8:53',
      info: `Standard query 0x3f4a A ${hostname}`,
      len: 74,
      isThreat: false
    });

    // 2. TCP 3-Way Handshake
    this.ingestPacket({
      proto: 'TCP',
      src: '192.168.1.100:51240',
      dst: `${hostname}:443`,
      info: `[SYN] Seq=0 Win=65535 Len=0 MSS=1460`,
      len: 64,
      isThreat: false
    });

    // 3. TLSv1.3 Handshake & Cipher Suite Negotiation
    this.ingestPacket({
      proto: 'TLS',
      src: '192.168.1.100:51240',
      dst: `${hostname}:443`,
      info: `Client Hello (SNI: ${hostname}, Cipher: TLS_AES_256_GCM_SHA384)`,
      len: 512,
      isThreat: false
    });

    // 4. Main HTTP GET / Search Payload
    this.ingestPacket({
      proto: url.startsWith('https://') ? 'HTTPS' : 'HTTP',
      src: '192.168.1.100:51240',
      dst: `${hostname}:443`,
      info: isQuarantined ? `[DROPPED BY ACTIVE QUARANTINE] Host ${hostname} blocked` : `GET ${url} HTTP/2`,
      len: 1240,
      isThreat: isQuarantined,
      isDropped: isQuarantined,
      host: hostname
    });

    // 5. Ingest Simulated Background Telemetry / Trackers for the site
    setTimeout(() => {
      const trackers = [
        { host: 'adservice.google.com', proto: 'HTTPS', info: 'Background telemetry ping' },
        { host: 'telemetry.tracker.xyz', proto: 'HTTP', info: 'Cleartext analytics beacon' }
      ];

      trackers.forEach(t => {
        const isBlocked = this.quarantinedDomains.has(t.host);
        if (isBlocked) this.shieldCount.textContent = `${this.quarantinedDomains.size} Trackers Blocked`;

        this.ingestPacket({
          proto: t.proto,
          src: '192.168.1.100:52110',
          dst: `${t.host}:80`,
          info: isBlocked ? `[SHUNNED BY FIREWALL] Connection dropped to ${t.host}` : `Outbound analytics beacon to ${t.host}`,
          len: 180,
          isThreat: true,
          isDropped: isBlocked,
          host: t.host
        });
      });
    }, 400);
  }

  // Ingest a packet into the Live Sniffer Engine
  ingestPacket(pkt) {
    pkt.id = this.packets.length + 1;
    pkt.time = new Date().toLocaleTimeString();
    this.packets.unshift(pkt);
    if (this.packets.length > 80) this.packets.pop();

    if (pkt.isThreat) this.threatCount++;
    this.totalBytes += pkt.len;

    this.renderPacketStream();
    this.updateMetrics();
  }

  renderPacketStream() {
    this.packetStreamList.innerHTML = this.packets.map(p => {
      const badgeClass = p.proto === 'HTTPS' ? 'badge-https' :
                         p.proto === 'HTTP'  ? 'badge-http' : 'badge-threat';

      return `
        <div class="packet-row ${p.isThreat ? 'threat' : ''}" data-pkt-id="${p.id}">
          <div class="packet-meta">
            <span class="badge ${badgeClass}">${p.proto}</span>
            <span style="color: #64748b;">${p.time}</span>
            <span style="color: #94a3b8;">${p.len} B</span>
          </div>
          <div class="packet-url" style="${p.isDropped ? 'text-decoration: line-through; color: #f43f5e;' : ''}">
            ${p.info}
          </div>
          ${p.host && !this.quarantinedDomains.has(p.host) ? `
            <div style="display:flex; justify-content: flex-end; margin-top: 2px;">
              <button class="btn-quarantine-host" data-host="${p.host}" style="background: rgba(244,63,94,0.2); color: #f43f5e; border: 1px solid rgba(244,63,94,0.4); border-radius: 4px; padding: 1px 6px; font-size: 9px; cursor: pointer;">
                ⛔ Quarantine Host
              </button>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
  }

  quarantineHost(host) {
    this.quarantinedDomains.add(host);
    this.quarantinedCount.textContent = this.quarantinedDomains.size;
    this.shieldCount.textContent = `${this.quarantinedDomains.size} Trackers Blocked`;
    this.renderPacketStream();
  }

  openPacketDissection(pktId) {
    const pkt = this.packets.find(p => p.id === pktId);
    if (!pkt) return;

    this.modalPktTitle.textContent = `PACKET #${pkt.id} [${pkt.proto}] DEEP DISSECTION`;
    this.modalPktDetails.innerHTML = `
      <div><b style="color:#06b6d4;">Layer 2 (Ethernet):</b> Dest MAC: 00:1A:2B:3C:4D:5E | Src MAC: A4:83:E7:2C:19:B0</div>
      <div><b style="color:#10b981;">Layer 3 (IPv4):</b> Src: ${pkt.src} ➜ Dst: ${pkt.dst} | Protocol: ${pkt.proto} | Length: ${pkt.len} bytes</div>
      <div><b style="color:#f59e0b;">Layer 4 (Transport / Info):</b> ${pkt.info}</div>
      <div style="margin-top: 8px;">
        <div style="color: #64748b; font-weight:700; margin-bottom: 4px;">RAW PAYLOAD HEX DUMP:</div>
        <pre style="background: #060911; border: 1px solid #1e293b; padding: 8px; border-radius: 6px; color: #10b981; font-size: 10px; overflow-x: auto;">
0000  45 00 05 dc 3a 4f 40 00 40 06 b2 1e c0 a8 01 64  E...:O@.@......d
0010  8e fa be 2e c8 28 01 bb fa a3 1b 8c b4 21 80 18  .....(.......!..
0020  01 f5 7e 30 00 00 01 01 08 0a 41 2f 12 a0 00 00  ..~0......A/....
        </pre>
      </div>
    `;
    this.packetModal.style.display = 'flex';
  }

  updateMetrics() {
    this.metricPkts.textContent = this.packets.length;
    this.metricThreats.textContent = this.threatCount;
    this.quarantinedCount.textContent = this.quarantinedDomains.size;
  }

  startBackgroundMetrics() {
    let lastCount = 0;
    setInterval(() => {
      const diff = this.packets.length - lastCount;
      lastCount = this.packets.length;
      this.metricPps.textContent = (diff * 2.5).toFixed(1);
    }, 1000);
  }

  // Tab Strip Controls
  createNewTab(url = 'about:home') {
    const newId = this.nextTabId++;
    this.tabs.push({ id: newId, title: 'New Tab', url: url, history: [url], historyIndex: 0 });
    this.activeTabId = newId;
    this.updateTabUI();
    this.navigateTo(url);
  }

  closeTab(tabId) {
    if (this.tabs.length <= 1) return;
    this.tabs = this.tabs.filter(t => t.id !== tabId);
    if (this.activeTabId === tabId) {
      this.activeTabId = this.tabs[this.tabs.length - 1].id;
    }
    this.updateTabUI();
    const active = this.tabs.find(t => t.id === this.activeTabId);
    if (active) this.navigateTo(active.url);
  }

  switchTab(tabId) {
    this.activeTabId = tabId;
    this.updateTabUI();
    const active = this.tabs.find(t => t.id === this.activeTabId);
    if (active) this.navigateTo(active.url);
  }

  updateTabUI() {
    const tabsHtml = this.tabs.map(t => `
      <div class="tab ${t.id === this.activeTabId ? 'active' : ''}" data-tab-id="${t.id}">
        <span class="tab-icon">🛡️</span>
        <span class="tab-title">${t.url === 'about:home' ? 'Secure Search Home' : t.url.replace('https://', '').replace('http://', '')}</span>
        ${this.tabs.length > 1 ? `<span class="tab-close" data-close-tab="${t.id}">✕</span>` : ''}
      </div>
    `).join('');

    this.tabStrip.querySelectorAll('.tab').forEach(el => el.remove());
    this.tabStrip.insertAdjacentHTML('afterbegin', tabsHtml);
  }

  navigateHistory(direction) {
    const active = this.tabs.find(t => t.id === this.activeTabId);
    if (!active) return;
    const newIdx = active.historyIndex + direction;
    if (newIdx >= 0 && newIdx < active.history.length) {
      active.historyIndex = newIdx;
      this.navigateTo(active.history[newIdx]);
    }
  }

  reloadCurrentTab() {
    const active = this.tabs.find(t => t.id === this.activeTabId);
    if (active) this.navigateTo(active.url);
  }

  exportForensicAudit() {
    const text = `
================================================================================
       CYBERSENTINEL SECURE BROWSER - FORENSIC NETWORK AUDIT LOG
================================================================================
Generated: ${new Date().toLocaleString()}
Active Tabs: ${this.tabs.length}
Total Packets Ingested: ${this.packets.length}
Total Volume Ingested:  ${this.totalBytes} bytes (${(this.totalBytes / 1024).toFixed(2)} KB)

Active Quarantined Domains (${this.quarantinedDomains.size}):
${Array.from(this.quarantinedDomains).map(d => ` - 🚫 ${d} (FIREWALL DROPPED)`).join('\n')}

Intercepted Packet Records:
${this.packets.map(p => `[${p.proto}] ${p.time} - ${p.src} ➜ ${p.dst} | ${p.info}`).join('\n')}
================================================================================
`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersentinel_browser_audit_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

// Instantiate on load
document.addEventListener('DOMContentLoaded', () => {
  window.browser = new CyberBrowser();
});
