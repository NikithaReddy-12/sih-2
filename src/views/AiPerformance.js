import { getBenchmark } from '../api/forecastClient.js';

const benchmarkState = { status: 'idle', data: null, error: '' };
const COMPARISON_MODELS = [
  { key: 'lstm', label: 'LSTM' },
  { key: 'logistic_window', label: 'Logistic (1 window)' },
  { key: 'logistic_flat10', label: 'Logistic (10 windows)' },
  { key: 'persistence', label: 'Persistence' },
];
const COMPARISON_HORIZONS = [0, 1, 3, 5];
let requestStarted = false;

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatMetric(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  const formatted = number.toFixed(4);
  return formatted.startsWith('-') ? `−${formatted.slice(1)}` : formatted;
}

function formatStat(value) {
  if (value && typeof value === 'object' && !Array.isArray(value) && ('mean' in value || 'std' in value)) {
    const mean = formatMetric(value.mean);
    const spread = value.std == null ? '' : ` ± ${formatMetric(value.std)}`;
    return `${mean}${spread}`;
  }
  if (typeof value === 'number') return formatMetric(value);
  if (value == null || value === '') return '—';
  if (typeof value === 'object') return escapeHtml(JSON.stringify(value));
  return escapeHtml(value);
}

function formatNoteText(value) {
  return escapeHtml(String(value ?? '').replace(/(^|[\s(])-(?=\d)/g, '$1−'));
}

function metricMean(value) {
  if (value == null || value === '') return null;
  const raw = value && typeof value === 'object' && !Array.isArray(value) && 'mean' in value
    ? value.mean
    : value;
  const number = Number(raw);
  return Number.isFinite(number) ? number : null;
}

function comparisonRows(data) {
  const metrics = Array.isArray(data?.metrics) ? data.metrics : [];
  const hostSource = metrics.some((row) => row.source === 'benchmark_v3_host.json')
    ? 'benchmark_v3_host.json'
    : null;
  return hostSource
    ? metrics.filter((row) => row.source === hostSource)
    : [];
}

function comparisonChart(title, metric, rows) {
  return `
    <div class="space-y-space-xs">
      <h3 class="font-label-caps text-label-caps text-on-surface uppercase">${escapeHtml(title)}</h3>
      <div class="space-y-space-xs">
        ${COMPARISON_MODELS.map(({ key, label }) => {
          const value = rows.find((row) => row.model === key && Number(row.horizon) === 3)?.[metric];
          const mean = metricMean(value);
          const width = mean == null ? 0 : Math.min(100, Math.max(0, mean * 100));
          return `
            <div class="grid grid-cols-[8rem_1fr_4rem] items-center gap-space-xs font-telemetry-sm text-telemetry-sm font-mono">
              <span class="truncate text-on-surface">${escapeHtml(label)}</span>
              <div class="h-2 bg-surface-container-highest/40 rounded-DEFAULT overflow-hidden" role="img" aria-label="${escapeHtml(label)} ${escapeHtml(title)} ${formatStat(value)}">
                <div class="${metric === 'fpr' ? 'bg-secondary' : 'bg-primary'} h-2" style="width:${width}%"></div>
              </div>
              <span class="text-right text-on-surface-variant">${formatStat(value)}</span>
            </div>`;
        }).join('')}
      </div>
    </div>`;
}

function benchmarkComparisonMarkup() {
  if (benchmarkState.status === 'loading' || benchmarkState.status === 'idle') {
    return '<p class="font-body-sm text-on-surface-variant">Loading full-data host benchmark scores.</p>';
  }
  if (benchmarkState.status === 'error') {
    return `<p class="font-body-sm text-error" role="alert">${escapeHtml(benchmarkState.error)}</p>`;
  }
  const rows = comparisonRows(benchmarkState.data);
  const metricFor = (model, horizon) => rows.find((row) => row.model === model && Number(row.horizon) === horizon);
  const macroRows = COMPARISON_MODELS.map(({ key, label }) => `
    <tr class="border-t border-surface-container-highest/30">
      <th scope="row" class="py-space-xs pr-space-sm text-on-surface font-medium">${escapeHtml(label)}</th>
      ${COMPARISON_HORIZONS.map((horizon) => `<td class="py-space-xs pr-space-sm text-on-surface">${formatStat(metricFor(key, horizon)?.f1)}</td>`).join('')}
    </tr>`).join('');
  const horizonThreeRows = COMPARISON_MODELS.map(({ key, label }) => {
    const row = metricFor(key, 3);
    return `
      <tr class="border-t border-surface-container-highest/30">
        <th scope="row" class="py-space-xs pr-space-sm text-on-surface font-medium">${escapeHtml(label)}</th>
        <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row?.precision)}</td>
        <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row?.recall)}</td>
        <td class="py-space-xs text-on-surface">${formatStat(row?.fpr)}</td>
      </tr>`;
  }).join('');
  return `
    <div class="space-y-space-md">
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <caption class="caption-top text-left font-label-caps text-label-caps text-on-surface-variant uppercase py-space-xs">Macro-F1 by forecast horizon</caption>
          <thead><tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
            <th class="py-space-xs pr-space-sm">Model</th>
            ${COMPARISON_HORIZONS.map((horizon) => `<th class="py-space-xs pr-space-sm">Horizon ${horizon}</th>`).join('')}
          </tr></thead>
          <tbody class="font-telemetry-sm text-telemetry-sm font-mono">${rows.length ? macroRows : '<tr><td colspan="5" class="py-space-xs text-on-surface-variant">No full-data host benchmark rows were returned.</td></tr>'}</tbody>
        </table>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <caption class="caption-top text-left font-label-caps text-label-caps text-on-surface-variant uppercase py-space-xs">Attack-versus-benign metrics · horizon 3</caption>
          <thead><tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
            <th class="py-space-xs pr-space-sm">Model</th><th class="py-space-xs pr-space-sm">Attack precision</th>
            <th class="py-space-xs pr-space-sm">Attack recall</th><th class="py-space-xs">Benign false-positive rate</th>
          </tr></thead>
          <tbody class="font-telemetry-sm text-telemetry-sm font-mono">
            ${rows.length ? horizonThreeRows : '<tr><td colspan="4" class="py-space-xs text-on-surface-variant">No full-data host benchmark rows were returned.</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-space-md">
        ${comparisonChart('False-positive rate · horizon 3', 'fpr', rows)}
        ${comparisonChart('Macro-F1 · horizon 3', 'f1', rows)}
      </div>
      <p class="font-body-sm text-on-surface-variant">Persistence has the highest macro-F1; the LSTM has far lower false positives. See the limits below.</p>
    </div>`;
}

function asRecords(value) {
  if (Array.isArray(value)) {
    return value.filter((row) => row && typeof row === 'object').map((row) => ({ ...row }));
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, row]) => (
      row && typeof row === 'object' && !Array.isArray(row) ? { name: key, ...row } : { name: key, value: row }
    ));
  }
  return [];
}

function recordTable(title, value) {
  const rows = asRecords(value);
  if (!rows.length) return '';
  const keys = [...new Set(rows.flatMap((row) => Object.keys(row)))];
  return `
    <section class="space-y-space-xs">
      <h3 class="font-label-caps text-label-caps text-on-surface uppercase">${escapeHtml(title)}</h3>
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <thead><tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
            ${keys.map((key) => `<th class="py-space-xs pr-space-sm">${escapeHtml(key)}</th>`).join('')}
          </tr></thead>
          <tbody class="font-telemetry-sm text-telemetry-sm font-mono">
            ${rows.map((row) => `<tr class="border-t border-surface-container-highest/30">${keys.map((key) => `<td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row[key])}</td>`).join('')}</tr>`).join('')}
          </tbody>
        </table>
      </div>
    </section>`;
}

function timeRange(value) {
  return Array.isArray(value) ? value.map((item) => escapeHtml(item)).join(' → ') : '—';
}

function stageCounts(counts) {
  if (!counts || typeof counts !== 'object') return '—';
  return Object.entries(counts).map(([name, count]) => `${escapeHtml(name)} ${formatStat(count)}`).join(', ');
}

function splitMarkup(split) {
  if (!split || typeof split !== 'object') return '';
  const sections = Object.entries(split).map(([source, info]) => {
    const pairs = Array.isArray(info.pair_counts)
      ? info.pair_counts.map((item) => `h${escapeHtml(item.horizon)}: train ${formatStat(item.n_train_pairs)}, test ${formatStat(item.n_test_pairs)}`).join('; ')
      : '';
    return `
      <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30 space-y-space-2xs">
        <div class="text-on-surface">${escapeHtml(source)}</div>
        <div>Method: ${escapeHtml(info.method || '—')}</div>
        ${info.gap_seconds != null ? `<div>Session gap: ${formatStat(info.gap_seconds)}s</div>` : ''}
        <div>Train time: ${timeRange(info.train_time)}</div><div>Test time: ${timeRange(info.test_time)}</div>
        ${info.n_train_episodes != null ? `<div>Episodes: train ${formatStat(info.n_train_episodes)}, test ${formatStat(info.n_test_episodes)}</div>` : ''}
        ${info.n_train_windows != null ? `<div>Windows: train ${formatStat(info.n_train_windows)}, test ${formatStat(info.n_test_windows)}</div>` : ''}
        ${info.train_stages ? `<div>Train stages: ${stageCounts(info.train_stages)}</div>` : ''}
        ${info.test_stages ? `<div>Test stages: ${stageCounts(info.test_stages)}</div>` : ''}
        ${pairs ? `<div>Horizon pairs: ${pairs}</div>` : ''}
        ${info.rule ? `<div>${escapeHtml(info.rule)}</div>` : ''}
      </div>`;
  }).join('');
  return `<section class="space-y-space-xs"><h3 class="font-label-caps text-label-caps text-on-surface uppercase">Split</h3><div class="grid grid-cols-1 md:grid-cols-2 gap-space-sm">${sections}</div></section>`;
}

function uniqueNotes(notes) {
  const values = Array.isArray(notes) ? notes : [];
  const seen = new Set();
  const entries = values.map((note) => typeof note === 'string'
    ? { source: '', name: 'note', text: note }
    : note && typeof note === 'object' ? note : null).filter((note) => note?.text);
  const networkVerdict = entries.find((note) => note.source === 'benchmark_v3.json' && note.name === 'verdict');
  const ordered = networkVerdict
    ? [networkVerdict, ...entries.filter((note) => note !== networkVerdict)]
    : entries;
  return ordered.filter((note) => {
    const key = String(note.text).trim().replace(/\s+/g, ' ').toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function procedureSeedSummary(notes) {
  const entries = Array.isArray(notes) ? notes : [];
  return entries.filter((note) => (
    note && typeof note === 'object' && ['procedure_full', 'procedure_budget'].includes(note.name)
  )).map((note) => {
    const full = note.name === 'procedure_full';
    const match = full
      ? String(note.text).match(/procedure on seeds ([\d,\s]+)/i)
      : String(note.text).match(/procedure, with seeds ([\d,\s]+)/i);
    if (!match) return '';
    const seeds = [...new Set(match[1].match(/\d+/g) || [])];
    if (!seeds.length) return '';
    const section = full
      ? 'Full-data main metrics, onset, per-stage, network alarm, and bootstrap'
      : 'Budgeted ablation, leave-one-attack-out, and cross-day';
    return `<li><strong>${escapeHtml(note.source || 'Benchmark')}</strong> · ${section}: seeds ${seeds.map(escapeHtml).join(', ')}</li>`;
  }).filter(Boolean);
}

function benchmarkMarkup() {
  if (benchmarkState.status === 'loading' || benchmarkState.status === 'idle') {
    return '<p class="font-body-sm text-on-surface-variant">Loading held-out benchmark scores.</p>';
  }
  if (benchmarkState.status === 'error') {
    return `<p class="font-body-sm text-error" role="alert">${escapeHtml(benchmarkState.error)}</p>`;
  }
  const data = benchmarkState.data || {};
  const metrics = Array.isArray(data.metrics) ? data.metrics : [];
  const notes = uniqueNotes(data.notes);
  const networkVerdict = notes.find((note) => note.source === 'benchmark_v3.json' && note.name === 'verdict');
  const remainingNotes = notes.filter((note) => note !== networkVerdict);
  const noteRows = [
    ...(networkVerdict ? [`<li><strong>Earlier network benchmark:</strong> ${formatNoteText(networkVerdict.text)}</li>`] : []),
    ...remainingNotes.map((note) => `<li>${note.source ? `<strong>${escapeHtml(note.source)}:</strong> ` : ''}${formatNoteText(note.text)}</li>`),
  ];
  const seedRows = procedureSeedSummary(data.notes);
  const split = data.split && typeof data.split === 'object' ? data.split : {};
  const metricRows = metrics.map((row) => `
    <tr class="border-t border-surface-container-highest/30">
      <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(row.model)}</td>
      <td class="py-space-xs pr-space-sm text-on-surface-variant">${escapeHtml(row.source)}</td>
      <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row.horizon)}</td>
      <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row.f1)}</td>
      <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row.precision)}</td>
      <td class="py-space-xs pr-space-sm text-on-surface">${formatStat(row.recall)}</td>
      <td class="py-space-xs text-on-surface">${formatStat(row.fpr)}</td>
    </tr>`).join('');
  const extras = [
    recordTable('Onset', data.onset),
    recordTable('Leave-one-attack-out', data.loao),
    recordTable('Ablation', data.ablation),
    recordTable('Per stage', data.per_stage),
  ].join('');

  return `
    ${notes.length ? `
      <section class="space-y-space-xs">
        <h3 class="font-label-caps text-label-caps text-on-surface uppercase">Notes</h3>
        <ul class="list-disc pl-space-md space-y-space-2xs font-body-sm text-on-surface-variant">${noteRows.join('')}</ul>
        ${seedRows.length ? `<ul class="list-disc pl-space-md space-y-space-2xs font-body-sm text-on-surface-variant">${seedRows.join('')}</ul>` : ''}
      </section>
    ` : '<p class="font-body-sm text-on-surface-variant" role="status">No benchmark notes returned.</p>'}
    ${metrics.length ? `
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <thead><tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
            <th class="py-space-xs pr-space-sm">Model</th><th class="py-space-xs pr-space-sm">Source</th>
            <th class="py-space-xs pr-space-sm">Horizon</th><th class="py-space-xs pr-space-sm">F1</th>
            <th class="py-space-xs pr-space-sm">Precision</th><th class="py-space-xs pr-space-sm">Recall</th><th class="py-space-xs">FPR</th>
          </tr></thead>
          <tbody class="font-telemetry-sm text-telemetry-sm font-mono">${metricRows}</tbody>
        </table>
      </div>
    ` : '<p class="font-body-sm text-on-surface-variant">No benchmark rows were returned.</p>'}
    ${extras}
    ${splitMarkup(split)}
  `;
}

export function renderAiPerformance(container) {
  const update = () => {
    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-lg">
        <section class="bg-surface-container rounded-DEFAULT p-space-md shadow-md space-y-space-sm border border-surface-container-high/40">
          <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold">LSTM vs logistic regression baselines (host level)</h1>
          ${benchmarkComparisonMarkup()}
        </section>
        <section class="bg-surface-container rounded-DEFAULT p-space-md shadow-md space-y-space-sm border border-surface-container-high/40">
          <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Held-out benchmark</h2>
          <p class="font-body-sm text-on-surface-variant">Scores, onset, leave-one-attack-out, and ablation come from GET /api/benchmark. A cell shows mean ± std only when the response includes both.</p>
          ${benchmarkMarkup()}
        </section>
      </div>`;
  };

  update();
  if (requestStarted) return;
  requestStarted = true;
  benchmarkState.status = 'loading';
  update();
  getBenchmark().then((data) => {
    benchmarkState.status = 'ready';
    benchmarkState.data = data;
    benchmarkState.error = '';
  }).catch((error) => {
    benchmarkState.status = 'error';
    benchmarkState.error = error.message || 'Benchmark request failed.';
  }).finally(update);
}
