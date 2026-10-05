import { store } from '../state/store.js';

export function renderHeader(container) {
  let notifOpen = false;

  const update = () => {
    const state = store.getState();
    const t = state.telemetry;
    const soundIcon = state.soundEnabled ? 'volume_up' : 'volume_off';

    container.innerHTML = `
      <header class="fixed top-0 left-64 right-0 h-16 bg-surface/90 backdrop-blur-xl z-40 flex items-center justify-between px-space-lg shadow-[0_1px_8px_rgba(0,0,0,0.04)] border-b border-surface-container-high/30">
        <!-- Search & Environment Selector -->
        <div class="flex items-center gap-space-md flex-1 max-w-2xl">
          <div class="relative flex items-center w-full max-w-md cursor-pointer" id="header-search-trigger">
            <span class="material-symbols-outlined absolute left-space-sm text-[18px] text-on-surface-variant pointer-events-none">search</span>
            <input 
              readonly
              class="w-full bg-surface-container-lowest text-on-surface placeholder:text-on-surface-variant/60 font-telemetry-sm text-telemetry-sm pl-9 pr-14 py-space-xs rounded-DEFAULT focus:outline-none focus:bg-surface-container cursor-pointer" 
              placeholder="Search assets, paths, alerts" 
              type="text"
            />
            <span class="absolute right-space-sm font-telemetry-sm text-telemetry-sm text-on-surface-variant bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT pointer-events-none">⌘K</span>
          </div>
          
          <div class="flex items-center gap-space-xs bg-surface-container-lowest px-space-sm py-space-xs rounded-DEFAULT">
              <span class="material-symbols-outlined text-primary text-[16px]">lock</span>
              <span class="font-body-sm text-body-sm text-on-surface font-medium">Dataset: CSE-CIC-IDS2018 (NetFlow-V3)</span>
          </div>
        </div>

        <!-- Telemetry Indicators & User Action Center -->
        <div class="flex items-center gap-space-md">
          <div class="hidden md:flex items-center gap-2 text-body-sm text-on-surface-variant" title="Forecasting engine online, average confidence ${t.avgConfidence}%">
            <span class="inline-block w-2 h-2 rounded-full bg-primary animate-pulse"></span>
            <span>Offline demo - no live feed</span>
          </div>

          <!-- Tactical Audio Toggle -->
          <button id="audio-toggle-btn" class="p-space-xs rounded-DEFAULT bg-surface-container-lowest text-on-surface-variant hover:text-primary transition-colors border border-surface-container-high/20" title="${state.soundEnabled ? 'Mute Sound Effects' : 'Enable Sound Effects'}">
            <span class="material-symbols-outlined text-[18px]">${soundIcon}</span>
          </button>

          <!-- Notifications Button & Popover -->
          <div class="relative">
            <button id="notif-btn" class="relative p-space-xs rounded-DEFAULT bg-surface-container-lowest text-on-surface-variant hover:text-on-surface transition-colors border border-surface-container-high/20">
              <span class="material-symbols-outlined text-[20px]">notifications</span>
            </button>

            ${notifOpen ? `
              <div id="notif-menu" class="absolute right-0 top-full mt-2 w-80 bg-surface-container-low border border-surface-container-highest rounded-DEFAULT shadow-2xl p-space-sm z-50">
                <div class="flex items-center justify-between pb-space-xs border-b border-surface-container-highest">
                  <span class="font-label-caps text-label-caps uppercase text-primary font-bold">Tactical Alerts</span>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Alerts</span>
                </div>
                <div class="space-y-space-xs my-space-xs max-h-64 overflow-y-auto">
                  ${state.notifications.map(n => `
                    <div class="p-space-xs rounded-DEFAULT ${n.read ? 'bg-surface-container' : 'bg-surface-container-lowest border-l-2 border-primary'}">
                      <div class="font-headline-md text-[12px] text-on-surface font-semibold">${n.title}</div>
                      <div class="font-body-sm text-[11px] text-on-surface-variant mt-0.5">${n.text}</div>
                      <div class="font-telemetry-sm text-[9px] text-primary mt-1">${n.time}</div>
                    </div>
                  `).join('')}
                </div>
                <button id="mark-all-read" class="w-full py-1 text-center font-telemetry-sm text-telemetry-sm text-primary hover:underline">
                  Mark all alerts as read
                </button>
              </div>
            ` : ''}
          </div>

          <div class="flex items-center gap-3 pl-3 border-l border-outline-variant/30">
            <span class="text-body-md text-on-surface hidden sm:block">Analyst</span>
            <button id="signout-btn" class="text-body-sm text-on-surface-variant hover:text-on-surface px-2 py-1 rounded-lg hover:bg-surface-container-high">Sign out</button>
          </div>
        </div>
      </header>
    `;

    // Bind event listeners
    const so=container.querySelector('#signout-btn'); if(so) so.addEventListener('click',()=>import('./Login.js').then(m=>m.signOut()));
    const searchTrigger = container.querySelector('#header-search-trigger');
    if (searchTrigger) {
      searchTrigger.addEventListener('click', () => store.setSearchModal(true));
    }

    const audioBtn = container.querySelector('#audio-toggle-btn');
    if (audioBtn) {
      audioBtn.addEventListener('click', () => store.toggleSound());
    }

    const notifBtn = container.querySelector('#notif-btn');
    if (notifBtn) {
      notifBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        notifOpen = !notifOpen;
        update();
      });
    }

    const markReadBtn = container.querySelector('#mark-all-read');
    if (markReadBtn) {
      markReadBtn.addEventListener('click', () => {
        store.state.notifications.forEach(n => n.read = true);
        notifOpen = false;
        store.notify();
      });
    }

  };

  update();
  store.subscribe(update);
}
