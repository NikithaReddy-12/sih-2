import { getLastForecast, getLastForecastLabel, subscribeLastForecast } from '../state/lastForecast.js';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function hostLabel(host) {
  const label = host.label_stage ?? host.dataset_label ?? host.label;
  const directLabel = label && typeof label === 'object' ? label.stage ?? label.label : label;
  return directLabel ?? getLastForecastLabel(host.host) ?? '—';
}

function hostBlock(rows, source) {
  return (Array.isArray(rows) ? rows : []).map((host) => {
    const probability = Number(host.peak_attack_prob);
    const severity = probability >= 0.9 ? 'high' : probability >= 0.5 ? 'medium' : 'low';
    const explanation = Array.isArray(host.explanation) ? host.explanation.slice(0, 5) : [];
    return `
      <tr class="border-t border-surface-container-highest/30 align-top">
        <td class="py-space-xs pr-space-sm text-on-surface font-mono">${escapeHtml(host.host || '—')}</td>
        <td class="py-space-xs pr-space-sm text-on-surface">${severity}</td>
        <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(host.stage || host.predicted_stage || '—')}</td>
        <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(host.mitre_tactic || host.tactic || '—')}</td>
        <td class="py-space-xs pr-space-sm text-on-surface font-mono">${Number.isFinite(probability) ? probability.toFixed(3) : '—'}</td>
        <td class="py-space-xs pr-space-sm text-on-surface-variant">${source}</td>
        <td class="py-space-xs text-on-surface-variant">${escapeHtml(hostLabel(host))}</td>
      </tr>
      <tr class="border-t border-surface-container-highest/20">
        <td colspan="7" class="py-space-xs">
          <details class="font-body-sm">
            <summary class="cursor-pointer text-primary">Explanation · ${escapeHtml(host.explanation_source || 'source not returned')}</summary>
            ${explanation.length ? `
              <ol class="list-decimal pl-space-md mt-space-xs space-y-space-2xs font-telemetry-sm text-telemetry-sm font-mono text-on-surface-variant">
                ${explanation.map((item) => `<li>${escapeHtml(item.name || 'feature')}${item.attribution != null ? ` · attribution ${escapeHtml(item.attribution)}` : ''}${item.value != null ? ` · value ${escapeHtml(item.value)}` : ''}</li>`).join('')}
              </ol>
            ` : '<p class="mt-space-xs text-on-surface-variant">No explanation returned.</p>'}
          </details>
        </td>
      </tr>`;
  }).join('');
}

let unsubscribeForecast = null;

export function renderAlerts(container) {
  const update = () => {
    const forecast = getLastForecast();
    if (!forecast) {
      container.innerHTML = `
        <section class="bg-surface-container rounded-DEFAULT p-space-md border border-surface-container-high/40 space-y-space-sm">
          <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold">Alerts</h1>
          <p class="font-body-md text-on-surface-variant">No forecast yet. Score a sample on the Risk forecast page.</p>
        </section>`;
      return;
    }
    const current = hostBlock(forecast.current_hosts, 'observed windows');
    const future = hostBlock(forecast.hosts, 'forecast');
    const table = (title, rows) => `
      <section class="bg-surface-container rounded-DEFAULT p-space-md border border-surface-container-high/40 space-y-space-sm">
        <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">${title}</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead><tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
              <th class="py-space-xs pr-space-sm">Host IP</th><th class="py-space-xs pr-space-sm">Severity</th>
              <th class="py-space-xs pr-space-sm">Predicted stage</th><th class="py-space-xs pr-space-sm">MITRE tactic</th>
              <th class="py-space-xs pr-space-sm">Peak probability</th><th class="py-space-xs pr-space-sm">Source</th>
              <th class="py-space-xs">Dataset label</th>
            </tr></thead>
            <tbody class="font-telemetry-sm text-telemetry-sm">${rows || '<tr><td colspan="7" class="py-space-xs text-on-surface-variant">No flagged hosts.</td></tr>'}</tbody>
          </table>
        </div>
      </section>`;
    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <section class="bg-surface-container rounded-DEFAULT p-space-md border border-surface-container-high/40 space-y-space-xs">
          <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold">Alerts</h1>
          <p class="font-body-sm text-on-surface-variant">Severity is a display threshold on model probability, not a calibrated risk.</p>
        </section>
        ${table('Current hosts', current)}
        ${table('Forecast hosts', future)}
      </div>`;
  };

  update();
  unsubscribeForecast?.();
  unsubscribeForecast = subscribeLastForecast(update);
}
