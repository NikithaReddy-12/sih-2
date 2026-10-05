import { store } from '../state/store.js';

export function renderSearchModal(container) {
  const searchableItems = [
    { category: 'Modules', title: 'Command Center', subtitle: 'Tactical Disruption & KPI Overview', action: () => store.setModule('command-center'), icon: 'terminal' },
    { category: 'Modules', title: 'Defense Simulation', subtitle: 'Test Mitigations in Ephemeral Sandbox', action: () => store.setModule('defense-simulation'), icon: 'shield_with_heart' },
    { category: 'Modules', title: 'Predicted Attack Path', subtitle: 'Probabilistic Neural Graph Analysis', action: () => store.setModule('predicted-attack-path'), icon: 'account_tree' },
    { category: 'Modules', title: 'AI Performance & Learning', subtitle: 'Bayesian Pipeline & Calibration Metrics', action: () => store.setModule('ai-performance-and-learning'), icon: 'psychology' },
    { category: 'Modules', title: 'Live Attack Investigation', subtitle: 'Real-Time Sensor & NDR Packet Inspector', action: () => store.setModule('live-attack-investigation'), icon: 'radar' },
    { category: 'Modules', title: 'Critical Assets', subtitle: 'Crown Jewels & Host Registry', action: () => store.setModule('critical-assets'), icon: 'hub' },
    { category: 'Nodes', title: 'PC-017 (Dev-Ops Workstation)', subtitle: '10.4.1.17 • Compromised • Primary Disruption Point', action: () => { store.setModule('critical-assets'); store.openNodeDetail('PC-017'); }, icon: 'laptop_mac' },
    { category: 'Nodes', title: 'SERVER-03 (App Server)', subtitle: '10.4.12.103 • Infiltrated Pivot • App Middleware', action: () => { store.setModule('critical-assets'); store.openNodeDetail('SERVER-03'); }, icon: 'dns' },
    { category: 'Nodes', title: 'ADMIN-02 (Privileged Jumphost)', subtitle: '10.4.12.5 • Predicted Next Target (87%)', action: () => { store.setModule('critical-assets'); store.openNodeDetail('ADMIN-02'); }, icon: 'admin_panel_settings' },
    { category: 'Nodes', title: 'DATABASE-01 (Customer SQL Cluster)', subtitle: '10.4.99.12 • Crown Jewel Target (4.8M records)', action: () => { store.setModule('critical-assets'); store.openNodeDetail('DATABASE-01'); }, icon: 'database' },
    { category: 'Cases', title: 'Case #PX-9821', subtitle: 'APT-29 Derivative • Active Campaign (91% Confidence)', action: () => { store.selectCase('PX-9821'); store.setModule('command-center'); }, icon: 'crisis_alert' },
    { category: 'Cases', title: 'Case #PX-9818', subtitle: 'Kerberoasting DC Escalation • Resolved', action: () => { store.selectCase('PX-9818'); store.setModule('attack-cases'); }, icon: 'work_history' },
    { category: 'IOCs & CVEs', title: 'CVE-2023-4966 (Citrix Bleed)', subtitle: 'Perimeter Exploit utilized by 194.26.29.112', action: () => store.setModule('threat-context'), icon: 'bug_report' },
    { category: 'IOCs & CVEs', title: '194.26.29.112 (Attacker Origin)', subtitle: 'AS49505 • St. Petersburg Proxy Cluster', action: () => store.setModule('threat-context'), icon: 'public_off' }
  ];

  let query = '';

  const update = () => {
    const state = store.getState();
    if (!state.searchModalOpen) {
      container.innerHTML = '';
      return;
    }

    const filtered = query.trim() === '' ? searchableItems : searchableItems.filter(item => 
      item.title.toLowerCase().includes(query.toLowerCase()) || 
      item.subtitle.toLowerCase().includes(query.toLowerCase()) ||
      item.category.toLowerCase().includes(query.toLowerCase())
    );

    container.innerHTML = `
      <div class="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-surface-container-lowest/80 backdrop-blur-md p-space-md" id="search-modal-backdrop">
        <div class="bg-surface-container-low max-w-2xl w-full rounded-DEFAULT shadow-2xl border border-surface-container-highest overflow-hidden animate-in fade-in zoom-in-95 duration-100">
          <div class="flex items-center px-space-md py-space-sm border-b border-surface-container-highest gap-space-sm">
            <span class="material-symbols-outlined text-primary text-[22px]">search</span>
            <input 
              id="search-omnibox-input"
              type="text" 
              value="${query}"
              placeholder="Search entities, attack paths, nodes, CVEs, IOCs..." 
              class="w-full bg-transparent text-on-surface font-telemetry-sm text-telemetry-sm focus:outline-none placeholder:text-on-surface-variant/50"
              autofocus
            />
            <span class="px-space-xs py-space-2xs bg-surface-container font-telemetry-sm text-telemetry-sm text-on-surface-variant rounded-DEFAULT">ESC</span>
          </div>

          <div class="max-h-96 overflow-y-auto p-space-xs space-y-1">
            ${filtered.length === 0 ? `
              <div class="py-space-xl text-center text-on-surface-variant font-body-sm text-body-sm">
                No matching telemetry entities found for "${query}"
              </div>
            ` : filtered.map((item, idx) => `
              <div 
                data-search-idx="${idx}"
                class="flex items-center justify-between p-space-sm rounded-DEFAULT hover:bg-surface-container-high cursor-pointer transition-colors group"
              >
                <div class="flex items-center gap-space-sm min-w-0">
                  <div class="w-8 h-8 rounded-DEFAULT bg-surface-container flex items-center justify-center text-primary group-hover:bg-primary group-hover:text-on-primary transition-colors shrink-0">
                    <span class="material-symbols-outlined text-[18px]">${item.icon}</span>
                  </div>
                  <div class="flex flex-col min-w-0">
                    <span class="font-headline-md text-[13px] text-on-surface font-semibold truncate">${item.title}</span>
                    <span class="font-telemetry-sm text-[11px] text-on-surface-variant truncate">${item.subtitle}</span>
                  </div>
                </div>
                <span class="font-label-caps text-[9px] uppercase px-space-xs py-space-2xs bg-surface-container rounded-DEFAULT text-primary-fixed-dim shrink-0">
                  ${item.category}
                </span>
              </div>
            `).join('')}
          </div>

          <div class="px-space-md py-space-xs bg-surface-container-lowest border-t border-surface-container-highest flex items-center justify-between font-telemetry-sm text-[10px] text-on-surface-variant">
            <span>Navigation: ↑ ↓ Enter to Select</span>
            <span>PREDICT-X Neural Index v4.2</span>
          </div>
        </div>
      </div>
    `;

    // Bind listeners
    const backdrop = container.querySelector('#search-modal-backdrop');
    if (backdrop) {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) {
          store.setSearchModal(false);
        }
      });
    }

    const input = container.querySelector('#search-omnibox-input');
    if (input) {
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
      input.addEventListener('input', (e) => {
        query = e.target.value;
        update();
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          store.setSearchModal(false);
        } else if (e.key === 'Enter' && filtered.length > 0) {
          filtered[0].action();
          store.setSearchModal(false);
        }
      });
    }

    container.querySelectorAll('[data-search-idx]').forEach(el => {
      el.addEventListener('click', () => {
        const idx = parseInt(el.getAttribute('data-search-idx'), 10);
        if (filtered[idx]) {
          filtered[idx].action();
          store.setSearchModal(false);
        }
      });
    });
  };

  // Keyboard shortcut listener for Cmd+K / Ctrl+K & Escape
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      const current = store.getState().searchModalOpen;
      store.setSearchModal(!current);
    }
    if (e.key === 'Escape' && store.getState().searchModalOpen) {
      store.setSearchModal(false);
    }
  });

  update();
  store.subscribe(update);
}
