import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';
import 'material-symbols/outlined.css';
import './style.css';
import { store } from './state/store.js';
import { telemetry } from './engine/telemetryGenerator.js';
import { renderSidebar } from './components/Sidebar.js';
import { renderHeader } from './components/Header.js';
import { renderSearchModal } from './components/SearchModal.js';
import { renderApprovalModal } from './components/ApprovalModal.js';
import { renderWorkflowBar } from './components/WorkflowBar.js';
import { renderLogin, isAuthed } from './components/Login.js';
import { renderLanding } from './components/Landing.js';
import { renderNodeDetailModal } from './components/NodeDetailModal.js';

import { renderCommandCenter } from './views/CommandCenter.js';
import { renderLiveAttackInvestigation } from './views/LiveAttackInvestigation.js';
import { renderPredictedAttackPath } from './views/PredictedAttackPath.js';
import { renderAttackForecast, stopAttackForecastReplay } from './views/AttackForecast.js';
import { renderAlerts } from './views/Alerts.js';
import { renderTargetRiskAnalysis } from './views/TargetRiskAnalysis.js';
import { renderDefenseSimulation } from './views/DefenseSimulation.js';
import { renderLiveBehaviourSignals } from './views/LiveBehaviourSignals.js';
import { renderAttackCases } from './views/AttackCases.js';
import { renderCriticalAssets } from './views/CriticalAssets.js';
import { renderThreatContext } from './views/ThreatContext.js';
import { renderAiPerformance } from './views/AiPerformance.js';
import { renderReports } from './views/Reports.js';
import { renderSettings } from './views/Settings.js';

// Route dictionary mapping module IDs to view renderers
const routes = {
  'command-center': renderCommandCenter,
  'live-attack-investigation': renderLiveAttackInvestigation,
  'predicted-attack-path': renderPredictedAttackPath,
  'attack-forecast': renderAttackForecast,
  alerts: renderAlerts,
  'target-risk-analysis': renderTargetRiskAnalysis,
  'defense-simulation': renderDefenseSimulation,
  'live-behaviour-signals': renderLiveBehaviourSignals,
  'attack-cases': renderAttackCases,
  'critical-assets': renderCriticalAssets,
  'threat-context': renderThreatContext,
  'ai-performance-and-learning': renderAiPerformance,
  'reports': renderReports,
  'settings': renderSettings
};

function initApp() {
  document.title = 'PREDICT-X';
  const gate = document.getElementById('login-container');
  if (!isAuthed()) {
    if (!window.location.hash) store.state.currentModule = 'attack-forecast';
    document.getElementById('app-shell').classList.add('hidden');
    renderLanding(gate, () => renderLogin(gate, bootShell));
  } else {
    bootShell();
  }
}

function bootShell() {
  document.getElementById('app-shell').classList.remove('hidden');
  renderWorkflowBar(document.getElementById('workflow-container'));
  const sidebarContainer = document.getElementById('sidebar-container');
  const headerContainer = document.getElementById('header-container');
  const mainContent = document.getElementById('main-content');
  const searchModalContainer = document.getElementById('search-modal-container');
  const approvalModalContainer = document.getElementById('approval-modal-container');
  const nodeModalContainer = document.getElementById('node-modal-container');

  // Render static frame components
  renderSidebar(sidebarContainer);
  renderHeader(headerContainer);
  renderSearchModal(searchModalContainer);
  renderApprovalModal(approvalModalContainer);
  renderNodeDetailModal(nodeModalContainer);

  let currentRenderedModule = null;
  if (!window.location.hash) store.state.currentModule = 'attack-forecast';

  // Render view router based on store module
  const routeView = () => {
    const state = store.getState();
    const activeModule = state.currentModule || 'attack-forecast';

    if (currentRenderedModule !== activeModule) {
      if (currentRenderedModule === 'attack-forecast') stopAttackForecastReplay();
      currentRenderedModule = activeModule;
      window.location.hash = activeModule;

      const renderer = routes[activeModule] || renderCommandCenter;
      store.beginView();
      mainContent.innerHTML = '';
      renderer(mainContent);
    }
  };

  // Sync hash routing on popstate / manual URL change
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '');
    if (routes[hash] && store.getState().currentModule !== hash) {
      store.setModule(hash);
    }
  });

  // Check initial hash
  const initialHash = window.location.hash.replace('#', '');
  if (routes[initialHash]) {
    store.state.currentModule = initialHash;
  }

  routeView();
  store.subscribe(routeView);

  // Start continuous telemetry ticker
  telemetry.start();
}

// Boot application when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
