import { store } from '../state/store.js';
import { STAGES, MORE_TOOLS } from './workflow.js';
import { brandLogoMarkup } from './BrandLogo.js';
import { flaggedHostCount, getLastForecast, subscribeLastForecast } from '../state/lastForecast.js';

const FORECAST = STAGES.find((stage) => stage.id === 'attack-forecast');
const ALERTS = { id: 'alerts', label: 'Alerts', icon: 'notifications' };
const AI_PERFORMANCE = MORE_TOOLS.find((item) => item.id === 'ai-performance-and-learning');

export function renderSidebar(container) {
  const update = () => {
    const current = store.getState().currentModule;
    const forecast = getLastForecast();
    const alertCount = flaggedHostCount(forecast);

    const link = (m, extra = '') => {
      const active = current === m.id;
      return `<a href="#${m.id}" data-module="${m.id}" ${active ? 'aria-current="page"' : ''}
        class="flex items-center gap-3 px-3 py-2 rounded-lg text-body-md transition-colors ${active ? 'bg-surface-container-high text-on-surface font-semibold' : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface'}">
        <span class="material-symbols-outlined text-[18px]">${m.icon}</span><span class="flex-1">${m.label}</span>${extra}</a>`;
    };

    const alertBadge = forecast
      ? `<span class="text-telemetry-sm bg-error-container text-on-error-container rounded-full px-1.5 py-0.5" aria-label="${alertCount} flagged hosts">${alertCount}</span>`
      : '';

    container.innerHTML = `
      <aside class="fixed left-0 top-0 h-full w-64 bg-surface-container-low z-50 flex flex-col border-r border-outline-variant/30">
        <div class="h-16 flex items-center px-4 border-b border-outline-variant/30">
          <span class="text-primary">${brandLogoMarkup('h-9 w-9')}</span>
          <span class="text-headline-md text-primary tracking-tight ml-2">PREDICT-X</span>
        </div>
        <nav class="flex-1 overflow-y-auto px-3 py-4 flex flex-col" aria-label="Analyst workflow">
          <div class="space-y-1">${link(FORECAST)}${link(ALERTS, alertBadge)}${link(AI_PERFORMANCE)}</div>
        </nav>
      </aside>`;

    container.querySelectorAll('[data-module]').forEach(a =>
      a.addEventListener('click', (e) => { e.preventDefault(); store.setModule(a.dataset.module); }));
  };

  update();
  store.subscribe(update);
  subscribeLastForecast(update);
}
