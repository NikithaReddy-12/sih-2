// Single source of truth for the analyst workflow (mirrors the end-to-end diagram)
export const STAGES = [
  { id: 'live-behaviour-signals', label: 'Behavioral understanding', hint: 'Recorded network behaviour', icon: 'activity_zone' },
  { id: 'command-center',         label: 'Dashboard',                hint: 'Overall risk at a glance',          icon: 'space_dashboard' },
  { id: 'attack-forecast',        label: 'Risk forecast',            hint: 'What is likely to happen next',     icon: 'online_prediction' },
  { id: 'predicted-attack-path',  label: 'Attack horizon',           hint: 'How an attacker could move',        icon: 'account_tree' },
  { id: 'defense-simulation',     label: 'Decision support',         hint: 'Choose and approve a response',     icon: 'shield_with_heart' }
];

export const SAVED_ALERTS = { id: 'attack-cases', label: 'Saved alerts', icon: 'bookmark' };

export const MORE_TOOLS = [
  { id: 'live-attack-investigation', label: 'Live investigation', icon: 'radar' },
  { id: 'target-risk-analysis', label: 'Target risk', icon: 'crisis_alert' },
  { id: 'critical-assets', label: 'Critical assets', icon: 'hub' },
  { id: 'threat-context', label: 'Threat context', icon: 'policy' },
  { id: 'ai-performance-and-learning', label: 'AI performance', icon: 'psychology' },
  { id: 'reports', label: 'Reports', icon: 'summarize' },
  { id: 'settings', label: 'Settings', icon: 'tune' }
];

export const stageIndex = (id) => STAGES.findIndex(s => s.id === id);
