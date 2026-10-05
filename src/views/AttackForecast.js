import { fetchSampleFile, getDemoForecast, getForecastStatus, getSamples, postHostForecast } from '../api/forecastClient.js';
import { setLastForecast } from '../state/lastForecast.js';

const HORIZONS = [1, 3, 5];
const PROTOTYPE_BANNER = '';

const ATTACK_STAGES = ['reconnaissance', 'initial_access', 'lateral_movement', 'command_and_control', 'exfiltration'];
const ACCEPTED = ['.csv.gz', '.csv', '.pcap', '.pcapng'];

const viewState = {
  horizonK: 3,
  file: null,
  mode: null,
  loading: false,
  error: '',
  forecast: null,
  samples: null,
  groundTruth: null,
  sampleName: '',
  supportedStages: null,
  selectedHost: null,
  resultName: '',
  replayIndex: null,
  replayPlaying: false,
  replaySpeed: 1,
  replayFinished: false,
  replayToast: null,
  replayThresholdAlerted: false,
};

let replayTimer = null;

export function stopAttackForecastReplay() {
  if (replayTimer) clearInterval(replayTimer);
  replayTimer = null;
  viewState.replayPlaying = false;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatProb(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(3) : '—';
}

function scoreableSample(name) {
  const lower = String(name || '').toLowerCase();
  return lower.endsWith('.csv.gz') || lower.endsWith('.csv') || lower.endsWith('.pcap') || lower.endsWith('.pcapng');
}

function formatRate(value) {
  if (value == null) return 'undefined';
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(3) : 'undefined';
}

function verdictFrom(detected, labelled, labelStage) {
  const byHost = new Map((labelled || []).map((row) => [row.host, row]));
  const flaggedRows = (detected || []).map((host) => {
    const label = byHost.get(host.host);
    const hostLabel = label ? label.stage : null;
    return {
      host: host.host,
      predicted_stage: host.stage,
      peak_attack_prob: host.peak_attack_prob,
      label_stage: hostLabel,
      stage_matched: hostLabel != null && host.stage === hostLabel,
      explanation_source: host.explanation_source,
    };
  });
  const flaggedHosts = new Set(flaggedRows.map((row) => row.host));
  const misses = (labelled || []).filter((row) => !flaggedHosts.has(row.host));
  const mismatches = flaggedRows.filter((row) => row.label_stage != null && !row.stage_matched);
  const unlabelled = flaggedRows.filter((row) => row.label_stage == null);
  const stageMatched = flaggedRows.filter((row) => row.label_stage != null && row.stage_matched).length;
  return {
    flaggedRows,
    misses,
    mismatches,
    unlabelled,
    host_precision: flaggedRows.length ? stageMatched / flaggedRows.length : null,
    host_recall: (labelled || []).length ? ((labelled || []).length - misses.length) / (labelled || []).length : null,
    stage_matched: stageMatched,
    stage_total: (labelled || []).length,
    flagged_unlabelled: unlabelled.length,
  };
}

function hostItems(rows, line) {
  if (!rows.length) return '<p class="font-body-sm text-on-surface-variant">None.</p>';
  return `<ul class="space-y-space-2xs">${rows.map(line).join('')}</ul>`;
}

function verdictColumn(title, block) {
  const source = title === 'Forecast' ? 'forecast_step_1' : 'observed_window';
  const flagged = (row) => `<li><button type="button" class="w-full text-left font-telemetry-sm text-telemetry-sm font-mono text-on-surface hover:text-primary" data-host-select="${source}:${escapeHtml(row.host)}">${escapeHtml(row.host)} · predicted ${escapeHtml(row.predicted_stage)} · dataset ${escapeHtml(row.label_stage || 'none')} · peak ${formatProb(row.peak_attack_prob)}</button></li>`;
  const mismatch = (row) => `<li class="font-telemetry-sm text-telemetry-sm font-mono text-on-surface">${escapeHtml(row.host)} · predicted ${escapeHtml(row.predicted_stage)} · dataset ${escapeHtml(row.label_stage)} · peak ${formatProb(row.peak_attack_prob)}</li>`;
  const unlabelled = (row) => `<li class="font-telemetry-sm text-telemetry-sm font-mono text-on-surface">${escapeHtml(row.host)} · predicted ${escapeHtml(row.predicted_stage)} · peak ${formatProb(row.peak_attack_prob)}</li>`;
  const missed = (row) => `<li class="font-telemetry-sm text-telemetry-sm font-mono text-on-surface">${escapeHtml(row.host)} · dataset ${escapeHtml(row.stage)}</li>`;
  return `
    <div class="space-y-space-xs">
      <h3 class="font-label-caps text-label-caps text-on-surface uppercase">${escapeHtml(title)}</h3>
      <p class="font-body-sm text-on-surface-variant">${block.stage_matched} of ${block.stage_total} labelled attackers flagged with the correct stage</p>
      <p class="font-body-sm text-on-surface-variant">${block.flagged_unlabelled} flagged hosts have no dataset label</p>
      <p class="font-label-caps text-label-caps text-on-surface-variant uppercase">Flagged ${block.flaggedRows.length}</p>
      ${hostItems(block.flaggedRows, flagged)}
      <p class="font-label-caps text-label-caps text-on-surface-variant uppercase">Missed attackers ${block.misses.length}</p>
      ${hostItems(block.misses, missed)}
      <p class="font-label-caps text-label-caps text-on-surface-variant uppercase">Stage mismatches ${block.mismatches.length}</p>
      ${hostItems(block.mismatches, mismatch)}
      <p class="font-label-caps text-label-caps text-on-surface-variant uppercase">Flagged without a dataset label ${block.unlabelled.length}</p>
      ${hostItems(block.unlabelled, unlabelled)}
    </div>
  `;
}

function datasetPanel(forecast) {
  if (/\.(pcap|pcapng)$/i.test(viewState.sampleName || viewState.file?.name || '')) return '';
  const saved = viewState.groundTruth?.samples?.[viewState.sampleName];
  if (!saved) return '';
  if (viewState.loading || !forecast) {
    return `
      <div class="bg-surface-container-low p-space-md rounded-DEFAULT border border-surface-container-high/40 font-body-sm text-on-surface-variant">
        Scoring ${escapeHtml(viewState.sampleName)}. Dataset labels load with the model output.
      </div>
    `;
  }
  const labelled = saved.labelled_attackers || [];
  const current = verdictFrom(forecast.current_hosts, labelled, saved.label_stage);
  const future = verdictFrom(forecast.hosts, labelled, saved.label_stage);
  const labelledLine = (row) => {
    const extra = Array.isArray(row.other_stages) && row.other_stages.length ? ` · also ${row.other_stages.map((stage) => escapeHtml(stage)).join(', ')}` : '';
    return `<li class="font-telemetry-sm text-telemetry-sm font-mono text-on-surface">${escapeHtml(row.host)} · dataset ${escapeHtml(row.stage)}${extra}</li>`;
  };
  return `
    <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-sm">
      <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Dataset labels</h2>
      <p class="font-body-sm text-on-surface-variant">Label stage ${escapeHtml(saved.label_stage || 'mixed')} · ${labelled.length} labelled attackers. Current detection uses the last 3 observed windows. Forecast uses flag basis future.</p>
      ${labelled.length ? `<ul class="space-y-space-2xs">${labelled.map(labelledLine).join('')}</ul>` : '<p class="font-body-sm text-on-surface-variant">No labelled attacker hosts.</p>'}
      <div class="grid grid-cols-1 md:grid-cols-2 gap-space-md">
        ${verdictColumn('Current detection', current)}
        ${verdictColumn('Forecast', future)}
      </div>
    </div>
  `;
}

function observedAttackProbability(timeline) {
  let best = null;
  for (const entry of timeline || []) {
    if (entry.observed !== true || entry.stage === 'benign') continue;
    const prob = Number(entry.prob);
    if (!Number.isFinite(prob)) continue;
    if (best === null || prob > best) best = prob;
  }
  return best;
}

function attackChartMarkup(timeline) {
  if (!timeline.length) return '';
  const labels = { benign: 'BEN', initial_access: 'IA', lateral_movement: 'LM', command_and_control: 'C2' };
  return `
    <div class="space-y-space-xs">
      <div class="font-label-caps text-label-caps text-on-surface-variant uppercase">Attack probability</div>
      <div class="flex items-end gap-space-2xs overflow-x-auto" role="img" aria-label="Attack probability for each timeline window, annotated with the stage">
        ${timeline.map((entry) => {
          const attack = Number(entry.attack_prob);
          const height = Number.isFinite(attack) ? Math.max(2, Math.round(attack * 96)) : 2;
          const tone = entry.observed ? 'bg-primary' : 'bg-secondary';
          return `
            <div class="flex flex-col items-center justify-end shrink-0 w-16">
              <span class="font-telemetry-sm text-[10px] text-on-surface font-mono">${formatProb(entry.attack_prob)}</span>
              <div class="${tone} w-3 rounded-sm" style="height:${height}px"></div>
              <span class="mt-1 font-telemetry-sm text-[10px] text-on-surface-variant font-mono text-center leading-tight">${escapeHtml(labels[entry.stage] || entry.stage)}</span>
            </div>
          `;
        }).join('')}
      </div>
      <div class="flex flex-wrap gap-space-sm font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">
        <span>BEN benign</span><span>IA initial access</span><span>LM lateral movement</span><span>C2 command and control</span>
      </div>
    </div>
  `;
}

function progressionMarkup(observedRows, futureRows) {
  const chain = observedRows.map((entry, index) => `
    ${index ? '<span class="text-on-surface-variant">→</span>' : ''}
    <span class="text-on-surface">${escapeHtml(entry.stage)}</span>
  `).join('');
  const steps = futureRows.map((entry, index) => {
    const horizon = index + 1;
    return `
      <div class="py-space-xs text-on-surface-variant">↓</div>
      <div>
        <div class="font-label-caps text-label-caps text-secondary uppercase">${index === 0 ? 'Predicted next' : 'Predicted follow-up'}</div>
        <div class="text-on-surface mt-space-2xs">${escapeHtml(entry.stage)}</div>
        <div class="text-on-surface-variant">Attack probability: ${formatProb(entry.attack_prob)}</div>
        <div class="text-on-surface-variant">Horizon: +${horizon} ${horizon === 1 ? 'window' : 'windows'}</div>
      </div>
    `;
  }).join('');
  return `
    <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT border border-surface-container-highest/30 font-telemetry-sm text-telemetry-sm font-mono">
      <div class="font-label-caps text-label-caps text-primary uppercase">Observed</div>
      <div class="flex flex-wrap items-center gap-x-space-xs gap-y-space-2xs mt-space-xs">${chain || '<span class="text-on-surface-variant">—</span>'}</div>
      ${steps}
    </div>
  `;
}

function notPredictedText(supported) {
  if (!Array.isArray(supported) || supported.length === 0) return '';
  const missing = ATTACK_STAGES.filter((stage) => !supported.includes(stage));
  return missing.length ? `Stages not predicted: ${missing.join(', ')}` : 'Stages not predicted: none';
}

function featureChartMarkup(explanation, method) {
  const items = explanation || [];
  if (!items.length) {
    return '<p class="font-body-sm text-on-surface-variant">No feature attributions in this response.</p>';
  }
  const groups = new Map();
  items.forEach((item) => {
    const key = item.horizon ?? item.step ?? 1;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  });
  return [...groups.entries()].map(([step, rows]) => {
    const bars = rows.map((item) => {
      const attribution = Number(item.attribution) || 0;
      const share = Number(item.share);
      const width = Number.isFinite(share) ? Math.max(2, Math.round(share * 100)) : 2;
      const group = String(item.group || item.kind).toUpperCase();
      const color = { FLOW: 'bg-primary', PACKET: 'bg-secondary', CONCENTRATION: 'bg-tertiary', CONTEXT: 'bg-outline' }[group];
      return `
        <div class="grid grid-cols-[8rem_1fr_auto] items-center gap-space-xs">
          <span class="truncate text-on-surface" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
          <div class="h-2 bg-surface-container-highest/40 rounded-DEFAULT overflow-hidden">
            <div class="${color} h-2" style="width:${width}%"></div>
          </div>
          <span class="text-on-surface-variant">${(Number.isFinite(share) ? `${(share * 100).toFixed(2)}%` : '—')} · ${attribution.toExponential(2)} · ${escapeHtml(group)}</span>
        </div>`;
    }).join('');
    const timestep = rows.find((item) => item.timestep != null);
    return `
      <div class="space-y-space-2xs">
        <div class="text-on-surface">Step +${escapeHtml(step)}${method ? ` · ${escapeHtml(method)}` : ''}${timestep ? ` · timestep ${escapeHtml(timestep.timestep)}` : ''}</div>
        ${bars}
      </div>`;
  }).join('');
}

function hostExplanationMarkup(host, method) {
  if (!host) return '';
  const source = host.explanation_source || 'forecast_step_1';
  const sourceLabel = source === 'observed_window' ? 'observed window' : 'forecast step +1';
  const flows = Array.isArray(host.flows_in_flagged_window) ? host.flows_in_flagged_window : [];
  return `
    <div class="space-y-space-xs">
      <h3 class="font-label-caps text-label-caps text-on-surface uppercase">Why host ${escapeHtml(host.host)} was flagged - ${sourceLabel}</h3>
      <p class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Method: ${escapeHtml(method || 'gradient_x_input_logodds')}</p>
      <div class="font-telemetry-sm text-telemetry-sm font-mono space-y-space-sm">${featureChartMarkup(host.explanation, method)}</div>
      <p class="font-body-sm text-on-surface-variant">Attribution of the log-odds of the predicted stage (gradient x input). It shows what the model is sensitive to, not causes.</p>
      <div class="space-y-space-xs">
        <h4 class="font-label-caps text-label-caps text-on-surface uppercase">Flows in the flagged window</h4>
        ${flows.length ? `
          <div class="overflow-x-auto">
            <table class="w-full text-left">
              <caption class="caption-bottom text-left py-space-xs font-body-sm text-on-surface-variant">Up to 5 flows from this host's peak window, ranked by how unusual the destination port is; these are not per-flow detections.</caption>
              <thead>
                <tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
                  <th class="py-space-xs pr-space-sm">Source</th>
                  <th class="py-space-xs pr-space-sm">Destination</th>
                  <th class="py-space-xs pr-space-sm">Destination port</th>
                  <th class="py-space-xs pr-space-sm">Protocol</th>
                  <th class="py-space-xs pr-space-sm">Bytes</th>
                  <th class="py-space-xs">TCP flags</th>
                </tr>
              </thead>
              <tbody class="font-telemetry-sm text-telemetry-sm font-mono">
                ${flows.map((flow) => `
                  <tr class="border-t border-surface-container-highest/30">
                    <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(flow.src_ip ?? '—')}</td>
                    <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(flow.dst_ip ?? '—')}</td>
                    <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(flow.dst_port ?? '—')}</td>
                    <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(flow.protocol ?? '—')}</td>
                    <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(flow.bytes ?? '—')}</td>
                    <td class="py-space-xs text-on-surface">${escapeHtml(flow.tcp_flags ?? '—')}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : '<p class="font-body-sm text-on-surface-variant" role="status">No flows returned</p>'}
      </div>
    </div>
  `;
}

function stageCoverageMarkup(forecast, supported) {
  if (!forecast) {
    return `
      <section class="bg-surface-container-low p-space-md rounded-DEFAULT border border-surface-container-high/40 space-y-space-xs" aria-label="Stage coverage">
        <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Stage coverage</h2>
        <p class="font-body-sm text-on-surface-variant">Load a host capture to retrieve stage coverage from the API.</p>
      </section>
    `;
  }
  const learnedStages = Array.isArray(forecast?.supported_stages)
    ? forecast.supported_stages
    : Array.isArray(supported) ? supported : [];
  const heuristicStages = new Set([
    ...(Array.isArray(forecast?.heuristic_stage_names) ? forecast.heuristic_stage_names : []),
    ...(Array.isArray(forecast?.heuristic_hosts) ? forecast.heuristic_hosts.map((hit) => hit.stage) : []),
  ]);
  const chips = ATTACK_STAGES.map((stage) => {
    const status = learnedStages.includes(stage)
      ? 'learned (LSTM)'
      : heuristicStages.has(stage) ? 'rule-based, unvalidated' : 'not covered';
    const tone = status === 'learned (LSTM)'
      ? 'bg-primary-container/40 text-on-surface border-primary/30'
      : status === 'rule-based, unvalidated'
        ? 'bg-secondary-container/30 text-on-surface border-secondary/30'
        : 'bg-surface-container-high text-on-surface-variant border-surface-container-highest/40';
    return `<span class="inline-flex items-center gap-space-2xs px-space-xs py-space-2xs rounded-DEFAULT border ${tone} font-body-sm"><span>${escapeHtml(stage.replace(/_/g, ' '))}</span><span class="font-label-caps text-label-caps">${escapeHtml(status)}</span></span>`;
  }).join('');
  return `
    <section class="bg-surface-container-low p-space-md rounded-DEFAULT border border-surface-container-high/40 space-y-space-xs" aria-label="Stage coverage">
      <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Stage coverage</h2>
      <div class="flex flex-wrap gap-space-xs">${chips}</div>
    </section>
  `;
}

function heuristicMarkup(forecast) {
  const hits = forecast?.heuristic_hosts || [];
  if (!hits.length) return '';
  const hasExfiltration = hits.some((hit) => hit.stage === 'exfiltration');
  return `
    <div class="bg-secondary-container/20 border border-secondary/40 p-space-md rounded-DEFAULT space-y-space-sm">
      <div class="flex items-center gap-space-xs">
        <span class="material-symbols-outlined text-secondary text-[18px]">rule</span>
        <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Heuristic stage signals</h2>
        <span class="px-space-xs py-space-2xs rounded-DEFAULT bg-secondary text-on-secondary font-label-caps text-label-caps uppercase">heuristic</span>
      </div>
      <p class="font-body-sm text-on-surface-variant">These rule-based signals are separate from the learned LSTM probability and benchmark.</p>
      ${hasExfiltration ? '<p class="font-body-sm text-on-surface-variant">Large transfers to internal servers (backups) can look like exfiltration.</p>' : ''}
      <div class="space-y-space-xs">
        ${hits.map((hit) => `
          <div class="bg-surface-container-lowest border border-surface-container-highest/30 p-space-sm rounded-DEFAULT">
            <div class="flex flex-wrap items-center gap-space-xs font-telemetry-sm text-telemetry-sm font-mono">
              <span class="text-on-surface">${escapeHtml(hit.host)}</span>
              <span class="text-secondary">${escapeHtml(hit.stage)}</span>
              <span class="px-space-xs py-space-2xs rounded-DEFAULT bg-secondary text-on-secondary text-[10px] uppercase">heuristic</span>
              <span class="text-on-surface-variant">score ${formatProb(hit.score)} · ${escapeHtml(hit.mitre_id)}</span>
            </div>
            <pre class="mt-space-xs whitespace-pre-wrap text-on-surface-variant font-telemetry-sm text-telemetry-sm font-mono">${escapeHtml(JSON.stringify(hit.rule_values))}</pre>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function modeLabel(forecast) {
  if (!forecast) return 'No capture loaded';
  if (forecast.model === 'cicids2018') return 'CIC-IDS-2018';
  if (forecast.model === 'logistic_regression') return 'Synthetic demo';
  return forecast.model;
}

function triggerReplayAlert(entry, index, timeline) {
  const probability = Number(entry.attack_prob);
  const thresholdReached = probability >= 0.9 && !viewState.replayThresholdAlerted;
  const previous = index > 0 ? timeline[index - 1] : null;
  const stageChanged = previous && previous.stage !== entry.stage;
  if (!thresholdReached && !stageChanged) return;
  if (thresholdReached) viewState.replayThresholdAlerted = true;
  viewState.replayToast = {
    probability: formatProb(entry.attack_prob),
    time: entry.t,
    stage: entry.stage,
    mitre: entry.mitre_id || 'MITRE ID unavailable',
  };
}

function downloadBlob(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function explanationReport(host, method) {
  const items = Array.isArray(host.explanation) ? host.explanation.slice(0, 5) : [];
  return `
    <section>
      <h4>Host ${escapeHtml(host.host || 'unknown')} · ${escapeHtml(host.explanation_source || 'source not returned')}</h4>
      <p>Method: ${escapeHtml(method || 'not returned')}</p>
      ${items.length
        ? `<ol>${items.map((item) => `<li>${escapeHtml(item.name || 'feature')}${item.attribution != null ? ` · attribution ${escapeHtml(item.attribution)}` : ''}${item.value != null ? ` · value ${escapeHtml(item.value)}` : ''}</li>`).join('')}</ol>`
        : '<p>No explanation returned.</p>'}
    </section>`;
}

function hostReportTable(title, hosts) {
  const rows = (Array.isArray(hosts) ? hosts : []).map((host) => `
    <tr>
      <td>${escapeHtml(host.host || '—')}</td><td>${escapeHtml(host.stage || host.predicted_stage || '—')}</td>
      <td>${escapeHtml(host.mitre_tactic || host.tactic || '—')}</td><td>${escapeHtml(host.mitre_id || '—')}</td>
      <td>${formatProb(host.peak_attack_prob)}</td>
    </tr>`).join('');
  return `
    <h3>${title}</h3>
    <table><thead><tr><th>Host</th><th>Predicted stage</th><th>MITRE tactic</th><th>MITRE ID</th><th>Peak probability</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5">No flagged hosts.</td></tr>'}</tbody></table>`;
}

function datasetReport(forecast) {
  const saved = viewState.groundTruth?.samples?.[viewState.sampleName];
  if (!saved) return '';
  const labelled = saved.labelled_attackers || [];
  const groups = [
    ['Current hosts', verdictFrom(forecast.current_hosts, labelled, saved.label_stage)],
    ['Forecast hosts', verdictFrom(forecast.hosts, labelled, saved.label_stage)],
  ];
  return `
    <section>
      <h2>Dataset-label comparison</h2>
      <p>Dataset label stage: ${escapeHtml(saved.label_stage || 'mixed')}</p>
      ${groups.map(([title, verdict]) => `
        <h3>${title}</h3>
        <table><thead><tr><th>Host</th><th>Predicted stage</th><th>Dataset label</th><th>Stage matched</th></tr></thead>
          <tbody>${verdict.flaggedRows.map((row) => `<tr><td>${escapeHtml(row.host)}</td><td>${escapeHtml(row.predicted_stage)}</td><td>${escapeHtml(row.label_stage || 'none')}</td><td>${row.stage_matched ? 'yes' : 'no'}</td></tr>`).join('') || '<tr><td colspan="4">No flagged hosts.</td></tr>'}
          ${verdict.misses.map((row) => `<tr><td>${escapeHtml(row.host)}</td><td>—</td><td>${escapeHtml(row.stage)}</td><td>missed</td></tr>`).join('')}</tbody>
        </table>`).join('')}
    </section>`;
}

function downloadHtmlReport(forecast) {
  const timeline = Array.isArray(forecast.timeline) ? forecast.timeline : [];
  const firstFuture = timeline.find((entry) => !entry.observed);
  const hosts = [
    ...(Array.isArray(forecast.current_hosts) ? forecast.current_hosts : []),
    ...(Array.isArray(forecast.hosts) ? forecast.hosts : []),
  ];
  const filename = viewState.resultName || viewState.sampleName || viewState.file?.name || 'recorded capture';
  const report = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>PREDICT-X report</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#18212b;background:#f7f8fa}
h1,h2,h3{line-height:1.2}section{margin:2rem 0}table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{text-align:left;padding:.55rem;border-bottom:1px solid #ccd2da}th{background:#e9edf2}small,.muted{color:#526070}li{margin:.3rem 0}
</style></head><body>
<h1>PREDICT-X forecast report</h1><p><strong>Sample or file:</strong> ${escapeHtml(filename)}</p><p><strong>Generated:</strong> ${escapeHtml(new Date().toLocaleString())}</p>
<section><h2>Forecast summary</h2><p><strong>Overall risk:</strong> ${formatProb(forecast.overall_risk)}</p>
<p><strong>Network risk definition:</strong> ${escapeHtml(forecast.network_risk_definition || 'Not returned')}</p>
<p><strong>Predicted stage:</strong> ${escapeHtml(firstFuture?.stage || 'Not returned')}</p>
<p><strong>MITRE tactic:</strong> ${escapeHtml(firstFuture?.tactic || 'Not returned')} · ${escapeHtml(firstFuture?.mitre_id || 'MITRE ID unavailable')}</p></section>
<section><h2>Flagged hosts</h2>${hostReportTable('Current hosts', forecast.current_hosts)}${hostReportTable('Forecast hosts', forecast.hosts)}</section>
<section><h2>Host explanations · top five</h2>${hosts.map((host) => explanationReport(host, forecast.method)).join('') || '<p>No host explanations returned.</p>'}</section>
${datasetReport(forecast)}
<section><h2>Limits</h2><ul><li>Labels are proxies.</li><li>Evaluation uses one dataset.</li><li>Rule-based reconnaissance and exfiltration signals are unvalidated.</li><li>Explanations show sensitivity and not causes.</li></ul></section>
</body></html>`;
  downloadBlob('predict-x-report.html', report, 'text/html;charset=utf-8');
}

export function renderAttackForecast(container) {
  stopAttackForecastReplay();
  const update = () => {
    const forecast = viewState.forecast;
    const timeline = forecast?.timeline || [];
    const replayActive = Boolean(forecast && viewState.replayIndex != null && !viewState.replayFinished);
    const visibleTimeline = replayActive ? timeline.slice(0, viewState.replayIndex + 1) : timeline;
    const observed = visibleTimeline.filter((entry) => entry.observed);
    const future = visibleTimeline.filter((entry) => !entry.observed);
    const attackProb = forecast?.model === 'cicids2018'
      ? (forecast.observed_attack_probability ?? null)
      : observedAttackProbability(timeline);
    const currentHostRows = (forecast?.current_hosts || []).map((host) => ({ ...host, _selectionKey: `observed_window:${host.host}` }));
    const forecastHostRows = (forecast?.hosts || []).map((host) => ({ ...host, _selectionKey: `forecast_step_1:${host.host}` }));
    const hostRows = [...currentHostRows, ...forecastHostRows];
    const selectedHost = hostRows.find((host) => host._selectionKey === viewState.selectedHost)
      || hostRows.find((host) => host.host === forecast?.explanation_host && host.explanation_source === 'forecast_step_1')
      || hostRows[0]
      || null;
    const supported = forecast?.supported_stages || viewState.supportedStages;
    const stageNote = notPredictedText(forecast?.not_predicted_stages ?? supported);
    const nextFuture = timeline.find((entry) => !entry.observed);
    const replayEntry = replayActive ? visibleTimeline[visibleTimeline.length - 1] : null;

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        ${PROTOTYPE_BANNER ? `
          <div class="px-space-sm py-space-xs rounded-DEFAULT border border-secondary/40 bg-secondary-container/20 text-on-surface font-body-sm" role="status">${escapeHtml(PROTOTYPE_BANNER)}</div>
        ` : ''}
        <div class="flex flex-col gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">online_prediction</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">NETFLOW-V3 HOST FORECAST</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">ATTACK TRAJECTORY FORECAST</h1>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Upload a NetFlow-V3 flow CSV or load a sample. Hosts are scored per 60-second window; future windows come from the host LSTM rollout (K=5).
            </p>
          </div>

          <div class="flex flex-wrap items-center gap-space-sm w-full min-w-0">
            <label class="shrink-0 inline-flex items-center px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high text-on-surface font-telemetry-sm text-telemetry-sm font-bold font-mono cursor-pointer border border-surface-container-highest/40">
              Choose file
              <input id="cic-file" type="file" accept=".csv,.csv.gz,.pcap,.pcapng,text/csv,application/vnd.tcpdump.pcap" class="sr-only" />
            </label>
            <span class="w-full font-body-sm text-on-surface-variant">Upload a NetFlow-V3 CSV or PCAP/PCAPNG capture.</span>
            <select id="sample-file" class="shrink-0 max-w-[14rem] px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high text-on-surface font-telemetry-sm text-telemetry-sm font-mono border border-surface-container-highest/40" ${viewState.loading ? 'disabled' : ''}>
              <option value="">${viewState.samples == null ? 'Loading samples' : viewState.samples.length ? 'Load a sample' : 'No sample files'}</option>
              ${(viewState.samples || []).filter(scoreableSample).map((name) => `<option value="${escapeHtml(name)}" ${name === viewState.sampleName ? 'selected' : ''}>${escapeHtml(name)}</option>`).join('')}
            </select>
            <span class="min-w-0 flex-1 truncate font-telemetry-sm text-telemetry-sm text-on-surface font-mono" title="${viewState.file ? escapeHtml(viewState.file.name) : ''}">${viewState.file ? escapeHtml(viewState.file.name) : 'No file selected'}</span>
            <button id="cic-upload" type="button" class="shrink-0 px-space-sm py-space-xs rounded-DEFAULT bg-primary text-on-primary font-telemetry-sm text-telemetry-sm font-bold font-mono cursor-pointer disabled:opacity-50" ${viewState.loading ? 'disabled' : ''}>
              ${viewState.loading && viewState.mode === 'cicids' ? 'Scoring…' : 'Score CSV'}
            </button>
            <button id="synthetic-demo" type="button" class="shrink-0 px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high text-on-surface font-telemetry-sm text-telemetry-sm font-bold font-mono cursor-pointer border border-surface-container-highest/40 disabled:opacity-50" ${viewState.loading ? 'disabled' : ''}>
              ${viewState.loading && viewState.mode === 'demo' ? 'Loading…' : 'Synthetic demo (older model)'}
            </button>
          </div>
        </div>

        <div class="flex items-center gap-space-xs bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30 w-fit">
          <span class="font-label-caps text-label-caps text-on-surface-variant uppercase px-1">FUTURE WINDOWS:</span>
          ${HORIZONS.map((horizon) => `
            <button type="button" class="px-space-sm py-space-xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold cursor-pointer font-mono ${viewState.horizonK === horizon ? 'bg-primary text-on-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface'}" data-horizon="${horizon}">
              ${horizon}
            </button>
          `).join('')}
        </div>

        <section class="bg-surface-container-low p-space-md rounded-DEFAULT border border-surface-container-high/40 space-y-space-xs">
          <p class="font-body-sm text-on-surface-variant">Replay of a recorded capture. The model scored the whole file first; this animation reveals the results one window at a time.</p>
          <div class="flex flex-wrap items-center gap-space-sm">
            <button id="replay-toggle" type="button" class="px-space-sm py-space-xs rounded-DEFAULT bg-primary-container text-on-primary-container font-body-sm font-semibold disabled:opacity-50" ${forecast?.timeline?.length ? '' : 'disabled'}>${viewState.replayPlaying ? 'Pause' : 'Play'}</button>
            <label for="replay-speed" class="font-body-sm text-on-surface-variant">Speed</label>
            <select id="replay-speed" class="px-space-xs py-space-2xs rounded-DEFAULT bg-surface-container-high text-on-surface font-body-sm" ${forecast?.timeline?.length ? '' : 'disabled'}>
              ${[1, 2, 4].map((speed) => `<option value="${speed}" ${viewState.replaySpeed === speed ? 'selected' : ''}>${speed}x</option>`).join('')}
            </select>
            <progress class="flex-1 min-w-32 h-2 accent-primary" max="${timeline.length || 1}" value="${forecast ? (viewState.replayFinished ? timeline.length : viewState.replayIndex == null ? 0 : viewState.replayIndex + 1) : 0}" aria-label="Replay progress"></progress>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${forecast ? `${viewState.replayFinished ? timeline.length : viewState.replayIndex == null ? 0 : viewState.replayIndex + 1} / ${timeline.length}` : '0 / 0'}</span>
            <button id="replay-restart" type="button" class="px-space-sm py-space-xs rounded-DEFAULT border border-surface-container-highest/40 text-on-surface font-body-sm disabled:opacity-50" ${forecast?.timeline?.length ? '' : 'disabled'}>Restart</button>
          </div>
        </section>
        <div class="flex flex-wrap gap-space-sm">
          <button id="download-html-report" type="button" class="px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high text-on-surface font-body-sm border border-surface-container-highest/40 disabled:opacity-50" ${forecast ? '' : 'disabled'}>Download report (HTML)</button>
          <button id="download-raw-result" type="button" class="px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high text-on-surface font-body-sm border border-surface-container-highest/40 disabled:opacity-50" ${forecast ? '' : 'disabled'}>Download raw result (JSON)</button>
        </div>

        ${viewState.error ? `
          <div class="bg-error-container/30 border border-error/40 text-on-error-container px-space-md py-space-sm rounded-DEFAULT font-body-sm" role="alert">${escapeHtml(viewState.error)}</div>
        ` : ''}
        ${viewState.replayToast ? `
          <div class="flex items-start justify-between gap-space-sm bg-error-container/40 border border-error/50 text-on-surface px-space-md py-space-sm rounded-DEFAULT font-body-sm" role="alert">
            <span>Alert: network risk ${escapeHtml(viewState.replayToast.probability)} at ${escapeHtml(viewState.replayToast.time)}, stage ${escapeHtml(viewState.replayToast.stage)}, ${escapeHtml(viewState.replayToast.mitre)}</span>
            <button id="dismiss-replay-alert" type="button" class="text-on-surface font-semibold" aria-label="Dismiss alert">Dismiss</button>
          </div>
        ` : ''}

        ${forecast?.model === 'logistic_regression' ? `
          <div class="bg-secondary-container/20 border border-secondary/40 text-on-surface px-space-md py-space-sm rounded-DEFAULT font-body-sm">
            Synthetic demo. Future steps are logistic horizons from baseline.joblib, not the CIC-IDS-2018 LSTM.
          </div>
        ` : ''}
        ${stageNote ? `
          <div class="bg-surface-container border border-surface-container-highest/40 text-on-surface-variant px-space-md py-space-sm rounded-DEFAULT font-body-sm">${escapeHtml(stageNote)}</div>
        ` : ''}
        ${stageCoverageMarkup(forecast, supported)}
        ${nextFuture && !replayActive ? `
          <div class="bg-surface-container-low px-space-md py-space-sm rounded-DEFAULT border border-surface-container-high/40 font-body-sm text-on-surface">
            Predicted stage ${escapeHtml(nextFuture.stage)} · ${escapeHtml(nextFuture.tactic || 'tactic not returned')}${nextFuture.mitre_id ? ` · ${escapeHtml(nextFuture.mitre_id)}` : ''}
            ${Array.isArray(nextFuture.techniques) && nextFuture.techniques.length ? ` · ${nextFuture.techniques.map((item) => escapeHtml(item)).join(', ')}` : ''}
          </div>
        ` : ''}

        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-space-sm">
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT border border-surface-container-high/40">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">OVERALL RISK</span>
            <div class="font-headline-lg text-primary font-bold my-1 font-mono">${!forecast || replayActive && !replayEntry ? '—' : formatProb(replayActive ? replayEntry.attack_prob : forecast.overall_risk)}</div>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${replayEntry ? `Replay window · ${escapeHtml(replayEntry.t)}` : `max future attack probability${forecast?.flag_basis ? ` · flag basis ${escapeHtml(forecast.flag_basis)}` : ''}`}</span>
          </div>
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT border border-surface-container-high/40">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">PREDICTED STAGE</span>
            <div class="font-headline-md text-on-surface font-bold my-1">${escapeHtml(replayActive ? replayEntry?.stage || '—' : nextFuture?.stage || '—')}</div>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${escapeHtml(replayActive ? replayEntry?.tactic || replayEntry?.mitre_id || '—' : nextFuture?.tactic || nextFuture?.mitre_id || 'No stage returned')}</span>
          </div>
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT border border-surface-container-high/40">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">OBSERVED ATTACK PROBABILITY</span>
            <div class="font-headline-lg text-secondary font-bold my-1 font-mono">${attackProb == null ? '—' : formatProb(attackProb)}</div>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${attackProb == null ? (forecast?.model === 'cicids2018' ? 'No observed attack in the capture' : 'No observed attack in the timeline') : 'Highest observed non-benign probability'}</span>
          </div>
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT border border-surface-container-high/40">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">MODEL</span>
            <div class="font-headline-lg text-on-surface font-bold my-1 font-mono text-[20px]">${escapeHtml(modeLabel(forecast))}</div>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${forecast ? `${forecast.windows} windows · horizon ${forecast.horizon_k}` : 'Waiting for a capture'}</span>
          </div>
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT border border-surface-container-high/40">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">SUGGESTED RESPONSE</span>
            <div class="font-body-sm text-on-surface my-1">${forecast?.next_action ? escapeHtml(forecast.next_action) : 'None returned'}</div>
            <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Static playbook text, not model output</span>
          </div>
        </div>

        ${forecast?.network_risk_definition ? `
          <p class="font-body-sm text-on-surface-variant">${escapeHtml(forecast.network_risk_definition)}</p>
        ` : ''}

        <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-md">
          <div class="flex items-center justify-between gap-space-sm flex-wrap">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">show_chart</span>
              <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Stage timeline</h2>
            </div>
            <div class="flex items-center gap-space-md font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">
              <span class="flex items-center gap-1"><span class="w-3 h-1 bg-primary inline-block"></span> Observed ${observed.length}</span>
              <span class="flex items-center gap-1"><span class="w-3 h-1 bg-secondary inline-block"></span> Predicted ${future.length}</span>
            </div>
          </div>

          ${timeline.length ? `
            ${replayActive && !visibleTimeline.length
              ? '<p class="font-body-sm text-on-surface-variant">Replay is at the beginning. Press Play to reveal the first window.</p>'
              : `
                ${attackChartMarkup(visibleTimeline)}
                ${progressionMarkup(observed, future)}
                <div class="overflow-x-auto">
                  <h3 class="font-label-caps text-label-caps text-on-surface uppercase mb-space-xs">Future steps</h3>
                  <table class="w-full text-left">
                    <thead>
                      <tr class="font-label-caps text-label-caps text-on-surface-variant uppercase">
                        <th class="py-space-xs pr-space-sm">Time</th>
                        <th class="py-space-xs pr-space-sm">Stage</th>
                        <th class="py-space-xs pr-space-sm">Attack probability</th>
                        <th class="py-space-xs pr-space-sm">Stage probability</th>
                        <th class="py-space-xs pr-space-sm">Tactic</th>
                        <th class="py-space-xs pr-space-sm">MITRE</th>
                        <th class="py-space-xs">Action</th>
                      </tr>
                    </thead>
                    <tbody class="font-telemetry-sm text-telemetry-sm font-mono">
                      ${future.length ? future.map((entry) => `
                        <tr class="border-t border-surface-container-highest/30 bg-secondary/5">
                          <td class="py-space-xs pr-space-sm text-on-surface">${escapeHtml(entry.t)}</td>
                          <td class="py-space-xs pr-space-sm text-secondary">${escapeHtml(entry.stage)}</td>
                          <td class="py-space-xs pr-space-sm text-on-surface">${formatProb(entry.attack_prob)}</td>
                          <td class="py-space-xs pr-space-sm text-on-surface">${formatProb(entry.prob)}</td>
                          <td class="py-space-xs pr-space-sm text-on-surface-variant">${escapeHtml(entry.tactic)}</td>
                          <td class="py-space-xs pr-space-sm text-on-surface-variant">${entry.mitre_id ? escapeHtml(entry.mitre_id) : '—'}</td>
                          <td class="py-space-xs text-on-surface-variant">${entry.action ? escapeHtml(entry.action) : '—'}</td>
                        </tr>
                      `).join('') : '<tr><td class="py-space-xs text-on-surface-variant" colspan="7">No future steps in this response.</td></tr>'}
                    </tbody>
                  </table>
                </div>
              `}
          ` : `
            <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT border border-surface-container-highest/30 font-body-sm text-on-surface-variant">
              No forecast yet. Load a sample or upload a NetFlow-V3 CSV.
            </div>
          `}

          ${selectedHost && !replayActive ? `
            <div class="space-y-space-xs">
              ${hostExplanationMarkup(selectedHost, forecast.method)}
              <div class="flex flex-wrap gap-space-sm font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono"><span class="text-primary">FLOW</span><span class="text-secondary">PACKET</span><span class="text-tertiary">CONCENTRATION</span><span class="text-outline">CONTEXT</span></div>
            </div>
          ` : ''}
        </div>

        ${replayActive ? '' : datasetPanel(forecast)}
        ${replayActive ? '' : heuristicMarkup(forecast)}
      </div>
    `;

    container.querySelector('#replay-toggle').addEventListener('click', () => {
      if (viewState.replayPlaying) {
        if (replayTimer) clearInterval(replayTimer);
        replayTimer = null;
        viewState.replayPlaying = false;
        update();
        return;
      }
      playReplay();
    });

    container.querySelector('#replay-speed').addEventListener('change', (event) => {
      viewState.replaySpeed = Number(event.target.value);
      if (viewState.replayPlaying) {
        if (replayTimer) clearInterval(replayTimer);
        replayTimer = setInterval(() => advanceReplay(), 1000 / viewState.replaySpeed);
      }
      update();
    });

    container.querySelector('#replay-restart').addEventListener('click', () => {
      if (replayTimer) clearInterval(replayTimer);
      replayTimer = null;
      viewState.replayIndex = -1;
      viewState.replayPlaying = false;
      viewState.replayFinished = false;
      viewState.replayToast = null;
      viewState.replayThresholdAlerted = false;
      update();
    });

    container.querySelector('#dismiss-replay-alert')?.addEventListener('click', () => {
      viewState.replayToast = null;
      update();
    });

    container.querySelector('#download-html-report').addEventListener('click', () => {
      if (viewState.forecast) downloadHtmlReport(viewState.forecast);
    });

    container.querySelector('#download-raw-result').addEventListener('click', () => {
      if (viewState.forecast) {
        downloadBlob('predict-x-result.json', JSON.stringify(viewState.forecast, null, 2), 'application/json;charset=utf-8');
      }
    });

    container.querySelector('#cic-file').addEventListener('change', (event) => {
      const selected = event.target.files?.[0] || null;
      const lower = selected ? selected.name.toLowerCase() : '';
      if (selected && !ACCEPTED.some((ext) => lower.endsWith(ext))) {
        viewState.file = null;
        viewState.error = 'Choose a .csv, .csv.gz, .pcap, or .pcapng file.';
        update();
        return;
      }
      viewState.file = selected;
      viewState.sampleName = '';
      if (selected) viewState.error = '';
      update();
    });

    container.querySelectorAll('[data-host-select]').forEach((button) => {
      button.addEventListener('click', () => {
        viewState.selectedHost = button.getAttribute('data-host-select');
        update();
      });
    });

    container.querySelector('#cic-upload').addEventListener('click', () => {
      if (!viewState.file) {
        viewState.error = 'Choose a .csv, .csv.gz, .pcap, or .pcapng file first.';
        update();
        return;
      }
      runForecast('cicids');
    });

    container.querySelector('#synthetic-demo').addEventListener('click', () => {
      runForecast('demo');
    });

    container.querySelector('#sample-file').addEventListener('change', async (event) => {
      const name = event.target.value;
      if (!name) return;
      if (replayTimer) clearInterval(replayTimer);
      replayTimer = null;
      viewState.replayPlaying = false;
      viewState.loading = true;
      viewState.error = '';
      viewState.mode = 'upload';
      viewState.sampleName = name;
      update();
      try {
        viewState.file = await fetchSampleFile(name);
        const forecast = await postHostForecast(viewState.file, viewState.horizonK);
        acceptForecast(forecast);
      } catch (error) {
        viewState.forecast = null;
        viewState.error = error.message || 'Forecast request failed.';
      } finally {
        viewState.loading = false;
        update();
      }
    });

    container.querySelectorAll('[data-horizon]').forEach((button) => {
      button.addEventListener('click', () => {
        const next = Number(button.getAttribute('data-horizon'));
        if (next === viewState.horizonK) return;
        viewState.horizonK = next;
        if (viewState.mode) runForecast(viewState.mode);
        else update();
      });
    });

  };

  function advanceReplay() {
    const timeline = Array.isArray(viewState.forecast?.timeline) ? viewState.forecast.timeline : [];
    const nextIndex = (viewState.replayIndex ?? -1) + 1;
    if (nextIndex >= timeline.length) {
      if (replayTimer) clearInterval(replayTimer);
      replayTimer = null;
      viewState.replayPlaying = false;
      viewState.replayFinished = true;
      update();
      return;
    }
    viewState.replayIndex = nextIndex;
    triggerReplayAlert(timeline[nextIndex], nextIndex, timeline);
    update();
  }

  function acceptForecast(forecast) {
    viewState.forecast = forecast;
    viewState.resultName = viewState.mode === 'demo'
      ? 'Synthetic demo'
      : viewState.sampleName || viewState.file?.name || 'recorded capture';
    viewState.replayIndex = null;
    viewState.replayPlaying = false;
    viewState.replayFinished = false;
    viewState.replayToast = null;
    viewState.replayThresholdAlerted = false;
    if (Array.isArray(forecast?.supported_stages)) {
      viewState.supportedStages = forecast.supported_stages;
    }
    const labels = viewState.groundTruth?.samples?.[viewState.sampleName]?.labelled_attackers || [];
    setLastForecast(forecast, labels);
  }

  function playReplay() {
    const timeline = Array.isArray(viewState.forecast?.timeline) ? viewState.forecast.timeline : [];
    if (!timeline.length) return;
    if (viewState.replayFinished) {
      viewState.replayIndex = -1;
      viewState.replayFinished = false;
      viewState.replayThresholdAlerted = false;
      viewState.replayToast = null;
    }
    if (viewState.replayIndex == null || viewState.replayIndex < 0) advanceReplay();
    if (viewState.replayFinished) return;
    viewState.replayPlaying = true;
    if (replayTimer) clearInterval(replayTimer);
    replayTimer = setInterval(() => advanceReplay(), 1000 / viewState.replaySpeed);
    update();
  }

  async function runForecast(mode) {
    if (replayTimer) clearInterval(replayTimer);
    replayTimer = null;
    viewState.replayPlaying = false;
    viewState.mode = mode;
    viewState.loading = true;
    viewState.error = '';
    update();
    try {
      const forecast = mode === 'demo'
        ? await getDemoForecast(viewState.horizonK)
        : await postHostForecast(viewState.file, viewState.horizonK);
      acceptForecast(forecast);
    } catch (error) {
      viewState.forecast = null;
      viewState.error = error.message || 'Forecast request failed.';
    } finally {
      viewState.loading = false;
      update();
    }
  }

  if (viewState.samples == null) {
    getSamples().then((data) => {
      viewState.samples = Array.isArray(data?.files) ? data.files : [];
      viewState.groundTruth = data?.ground_truth || null;
    }).catch((error) => {
      viewState.samples = [];
      viewState.error = error.message || 'Could not load sample files.';
    }).finally(update);
  }
  if (viewState.supportedStages == null) {
    getForecastStatus().then((data) => {
      const stages = data?.modes?.cicids2018?.supported_stages;
      if (Array.isArray(stages)) viewState.supportedStages = stages;
    }).catch(() => {}).finally(update);
  }

  update();
}
