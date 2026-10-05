import { audio } from '../engine/audio.js';

class Store {
  constructor() {
    this.listeners = new Set();

    this.state = {
      currentModule: 'attack-forecast',
      activeCaseId: 'PX-9821',
      selectedNode: null,
      searchModalOpen: false,
      approvalModalOpen: false,
      nodeDetailModalOpen: false,
      recalibrating: false,
      retraining: false,
      activeSimulationOption: 'option-2',
      simulationApplied: false,
      approvalTicket: null,
      timelineFilter: 'ALL',
      soundEnabled: true,
      
      // Global live metrics
      telemetry: {
        eps: 42819,
        activeCases: 7,
        observedEvents: 12,
        predictedPaths: 5,
        criticalTargets: 4,
        overallRisk: 78,
        dbCompromise: 68,
        eventsToday: '12.8M',
        avgConfidence: 91,
        latency: '1.4s',
        modelOnline: true,
        epoch: 4912,
        lossL1: 0.0412,
        brierScore: 0.089,
        ece: 0.031
      },

      // Nodes topology registry
      nodes: {
        'EXT-01': {
          id: 'EXT-01',
          name: 'EXTERNAL ACTOR',
          ip: '194.26.29.112',
          asn: 'AS49505',
          location: 'St. Petersburg, RU (Proxy / Tor Exit)',
          role: 'Infiltration Origin',
          tier: 'Adversary',
          cve: 'CVE-2023-4966 (Citrix Bleed)',
          status: 'ATTACKING',
          compromised: true,
          isolated: false
        },
        'PC-017': {
          id: 'PC-017',
          name: 'PC-017 (Dev-Ops Workstation)',
          hostname: 'dev-wks-017.lan',
          ip: '10.4.1.17',
          subnet: '10.4.1.0/24',
          role: 'Developer Workstation',
          os: 'Windows 11 Enterprise (Build 22631)',
          tier: 'Tier 3 (User)',
          riskScore: 91,
          status: 'COMPROMISED',
          isolated: false,
          cves: ['CVE-2023-4966', 'CVE-2024-21413'],
          agentStatus: 'Sensor-Active (EDR v4.2)',
          user: 'j.miller (Lead Backend Eng)'
        },
        'SERVER-03': {
          id: 'SERVER-03',
          name: 'SERVER-03 (App Server / Core LAN)',
          hostname: 'app-srv-03.internal',
          ip: '10.4.12.103',
          subnet: '10.4.12.0/24',
          role: 'App Middleware & Microservices',
          os: 'Linux Kernel 5.15 LTS (Ubuntu 22.04)',
          tier: 'Tier 2 (Internal)',
          riskScore: 96,
          status: 'INFILTRATED_PIVOT',
          isolated: false,
          cves: ['CVE-2023-38606', 'CVE-2024-1086'],
          agentStatus: 'NDR Tap + Host Agent',
          user: 'svc-billing-daemon'
        },
        'ADMIN-02': {
          id: 'ADMIN-02',
          name: 'ADMIN-02 (Privileged Jumphost)',
          hostname: 'admin-jump-02.sec.corp',
          ip: '10.4.12.5',
          subnet: '10.4.12.0/24',
          role: 'Core Jumpbox Console / Bastion',
          os: 'Windows Server 2022 Datacenter',
          tier: 'Tier 1 (High Sec)',
          riskScore: 84,
          status: 'PREDICTED_NEXT',
          isolated: false,
          cves: ['CVE-2022-21907'],
          agentStatus: 'Privileged Access Monitor',
          user: 'svc-jump-admin'
        },
        'DATABASE-01': {
          id: 'DATABASE-01',
          name: 'DATABASE-01 (Customer SQL Cluster)',
          hostname: 'prod-sql-cluster-01.vault',
          ip: '10.4.99.12',
          subnet: '10.4.99.0/24',
          role: 'Production Financial Core Vault',
          os: 'RHEL 9.2 Enterprise (Hardened)',
          tier: 'Tier 0 (Crown Jewel)',
          riskScore: 68,
          status: 'CROWN_JEWEL_EXPOSED',
          isolated: false,
          cves: ['PCI-DSS High Impact'],
          agentStatus: 'Database Activity Audit',
          records: '4.8M Customer Transactions'
        },
        'IDENTITY-SERVER': {
          id: 'IDENTITY-SERVER',
          name: 'IDENTITY-SERVER (AD Domain Controller)',
          hostname: 'dc-02.corp.lan',
          ip: '10.4.12.18',
          subnet: '10.4.12.0/24',
          role: 'Active Directory DC-02',
          os: 'Windows Server 2022 Datacenter',
          tier: 'Tier 0 (Identity)',
          riskScore: 62,
          status: 'ALT_BRANCH',
          isolated: false,
          cves: ['CVE-2022-37969'],
          agentStatus: 'Identity Threat Sensor'
        },
        'FILE-07': {
          id: 'FILE-07',
          name: 'FILE-07 (Internal SMB Share)',
          hostname: 'nas-eng-file07.storage',
          ip: '10.4.14.80',
          subnet: '10.4.14.0/24',
          role: 'NAS Engineering Storage',
          os: 'TrueNAS Enterprise v13.0',
          tier: 'Tier 2 (Storage)',
          riskScore: 55,
          status: 'ALT_BRANCH',
          isolated: false,
          cves: [],
          agentStatus: 'File Integrity Monitor'
        }
      },

      // Simulation Options & Outcomes
      simulationScenarios: {
        'option-1': {
          id: 'option-1',
          title: 'Option 1: Block source IP',
          target: '194.26.29.112 (Perimeter Firewall Egress/Ingress)',
          effectiveness: 68,
          operationalImpact: 'LOW (0 Outage)',
          impactClass: 'text-primary',
          tradeoff: 'Attacker already established internal persistence on PC-017 via encrypted C2 fallback.',
          statusLabel: 'SUB-OPTIMAL',
          statusClass: 'bg-surface-container text-on-surface-variant',
          newRiskScore: 72,
          newDbProb: 52,
          killChainState: 'PARTIAL (C2 Disrupted)',
          disruptionGain: 28.4
        },
        'option-2': {
          id: 'option-2',
          title: 'Option 2: Isolate PC-017',
          target: 'Zero-Trust EDR Host Quarantine Trigger',
          effectiveness: 94,
          operationalImpact: 'LOW (1 User)',
          impactClass: 'text-primary font-semibold',
          tradeoff: 'Isolates 1 endpoint, 1 user affected. Disconnects socket to SERVER-03 without production loss.',
          statusLabel: 'ACTIVE PICK (RECOMMENDED)',
          statusClass: 'bg-primary/20 text-primary font-bold',
          newRiskScore: 38,
          newDbProb: 14,
          killChainState: 'SEVERED AT HOP 1',
          disruptionGain: 94.2
        },
        'option-3': {
          id: 'option-3',
          title: 'Option 3: Disable Credentials',
          target: 'Identity Revocation: svc-backup-admin',
          effectiveness: 86,
          operationalImpact: 'MEDIUM (Backups)',
          impactClass: 'text-secondary',
          tradeoff: 'May pause scheduled night-shift backups across disaster recovery cluster.',
          statusLabel: 'ALTERNATE',
          statusClass: 'bg-surface-container text-on-surface-variant',
          newRiskScore: 49,
          newDbProb: 28,
          killChainState: 'CREDENTIAL REVOKED',
          disruptionGain: 61.5
        },
        'option-4': {
          id: 'option-4',
          title: 'Option 4: Segment ADMIN-02',
          target: 'Micro-Segmentation vs DATABASE-01',
          effectiveness: 91,
          operationalImpact: 'MEDIUM (Admin Access)',
          impactClass: 'text-secondary',
          tradeoff: 'Emergency firewall rule drops management console during active maintenance cycle.',
          statusLabel: 'STANDBY',
          statusClass: 'bg-surface-container text-on-surface-variant',
          newRiskScore: 42,
          newDbProb: 20,
          killChainState: 'BASTION ISOLATED',
          disruptionGain: 84.0
        },
        'option-5': {
          id: 'option-5',
          title: 'Option 5: Isolate DATABASE-01',
          target: 'Total Infrastructure Port Scram',
          effectiveness: 99,
          operationalImpact: 'CRITICAL (45k Users)',
          impactClass: 'text-error font-bold',
          tradeoff: 'Brings down production transaction processing for 45,000 active banking clients immediately.',
          statusLabel: 'EXCESSIVE BLAST',
          statusClass: 'bg-error-container/40 text-error',
          newRiskScore: 25,
          newDbProb: 2,
          killChainState: 'CLUSTER OFFLINE',
          disruptionGain: 98.8
        }
      },

      // Available Threat Cases
      cases: [
        {
          id: 'PX-9821',
          title: 'Case #PX-9821: APT-29 Derivative Campaign',
          attacker: '194.26.29.112 (Cozy Bear proxy)',
          observedHops: 'PC-017 → SERVER-03',
          predictedHops: 'SERVER-03 → ADMIN-02 → DATABASE-01',
          severity: 'CRITICAL',
          confidence: '91%',
          status: 'ACTIVE_INTERCEPT_PENDING',
          updated: 'Just now'
        },
        {
          id: 'PX-9818',
          title: 'Case #PX-9818: Kerberoasting Escalation',
          attacker: '185.190.140.32',
          observedHops: 'WS-104 → DC-01',
          predictedHops: 'DC-01 → SEC-VAULT',
          severity: 'HIGH',
          confidence: '87%',
          status: 'RESOLVED_CONTAINED',
          updated: '28m ago'
        },
        {
          id: 'PX-9815',
          title: 'Case #PX-9815: Vault Probe & Token Replay',
          attacker: '45.154.255.89',
          observedHops: 'API-GW → SEC-VAULT-01',
          predictedHops: 'SEC-VAULT-01 → BACKUP-POOL',
          severity: 'HIGH',
          confidence: '92%',
          status: 'RESOLVED_CONTAINED',
          updated: '1h ago'
        },
        {
          id: 'PX-9810',
          title: 'Case #PX-9810: Initial Citrix Perimeter Probe',
          attacker: '194.26.29.112',
          observedHops: 'EXT → WS-902',
          predictedHops: 'WS-902 → DMZ-SWITCH',
          severity: 'MEDIUM',
          confidence: '64%',
          status: 'DISRUPTED',
          updated: '2h ago'
        }
      ],

      // Live Attack Evolution Timeline items
      timeline: [
        {
          id: 'ev-1',
          time: '10:01:14',
          type: 'OBSERVED',
          badgeClass: 'bg-error-container/30 text-error',
          borderClass: 'bg-error',
          title: 'Port scanning detected',
          details: 'Source IP: 194.26.29.112 → PC-017 [Port 445, 3389, 8080]',
          icon: 'radar',
          actor: '194.26.29.112',
          target: 'PC-017'
        },
        {
          id: 'ev-2',
          time: '10:04:32',
          type: 'OBSERVED',
          badgeClass: 'bg-error-container/30 text-error',
          borderClass: 'bg-error',
          title: 'Service enumeration detected on SMB port 445',
          details: 'Target: 10.0.4.12 [PC-017] • Anonymous IPC$ pipe query',
          icon: 'search',
          actor: '194.26.29.112',
          target: 'PC-017'
        },
        {
          id: 'ev-3',
          time: '10:06:50',
          type: 'OBSERVED',
          badgeClass: 'bg-error-container/30 text-error',
          borderClass: 'bg-error',
          title: 'Repeated authentication probing on local service accounts',
          details: '24 failures / 40 sec • Account: dev-admin, svc-build',
          icon: 'lock_clock',
          actor: '194.26.29.112',
          target: 'PC-017'
        },
        {
          id: 'ev-4',
          time: '10:07:22',
          type: 'PREDICTED',
          badgeClass: 'bg-primary-container text-on-primary-container',
          borderClass: 'bg-primary-container',
          title: 'Credential compromise probability increased to 58%',
          details: 'Predictive Vector PX-GEN-3 • Cached LSASS token discovered',
          icon: 'online_prediction',
          actor: 'Heuristic Engine',
          target: 'PC-017'
        },
        {
          id: 'ev-5',
          time: '10:09:11',
          type: 'OBSERVED',
          badgeClass: 'bg-error-container/30 text-error',
          borderClass: 'bg-error',
          title: 'Internal lateral movement detected: PC-017 → SERVER-03',
          details: 'Privilege token hijacked: svc-billing-daemon PsExec invocation',
          icon: 'trending_up',
          actor: 'PC-017',
          target: 'SERVER-03'
        },
        {
          id: 'ev-6',
          time: '10:10:04',
          type: 'PREDICTED',
          badgeClass: 'bg-primary text-on-primary font-bold',
          borderClass: 'bg-primary-container',
          title: 'ADMIN-02 identified as likely next target. Probability 87%',
          details: '(Est. 4–7 min window until execution) • Vector: Kerberos RDP probe',
          icon: 'cyclone',
          actor: 'Neural Forecaster',
          target: 'ADMIN-02'
        },
        {
          id: 'ev-7',
          time: '10:11:42',
          type: 'RECOMMENDED',
          badgeClass: 'bg-secondary text-on-secondary font-bold',
          borderClass: 'bg-secondary',
          title: 'Proactive defense action recommended: Isolate PC-017 to disrupt path.',
          details: 'Will prevent traversal reach to DATABASE-01 • Efficacy: 94.2%',
          icon: 'priority_high',
          actor: 'Tactical Disruption Engine',
          target: 'PC-017'
        }
      ],

      // Notifications
      notifications: [
        {
          id: 'n-1',
          title: 'Critical Threat Path Detected',
          text: 'Campaign #PX-9821 convergence probability toward DATABASE-01 exceeded 65%.',
          time: '2m ago',
          read: false,
          type: 'critical'
        },
        {
          id: 'n-2',
          title: 'Model Learning Cycle Complete',
          text: 'Neural Forecaster v4.2.8 updated priors with 1,420 newly verified telemetry records.',
          time: '22m ago',
          read: false,
          type: 'info'
        },
        {
          id: 'n-3',
          title: 'SOC Policy IR-402 Sync',
          text: 'Disruption simulation verified non-destructive dry run credentials.',
          time: '45m ago',
          read: false,
          type: 'success'
        }
      ],

      // Audit validation logs
      auditLogs: [
        {
          time: '10:10:04',
          campaign: 'PX-9821',
          stage: 'Lateral Movement',
          target: 'ADMIN-02',
          prob: '87%',
          outcome: 'Awaiting telemetry endpoint sync',
          eval: 'Pending (7m Horizon)',
          badge: 'bg-primary-container/20 text-primary'
        },
        {
          time: '09:44:12',
          campaign: 'PX-9818',
          stage: 'Lateral Movement',
          target: 'ADMIN-02',
          prob: '87%',
          outcome: 'ADMIN-02 RDP Probe Detected',
          eval: 'Correct',
          badge: 'bg-primary/10 text-primary'
        },
        {
          time: '09:12:00',
          campaign: 'PX-9815',
          stage: 'Credential Access',
          target: 'SEC-VAULT-01',
          prob: '92%',
          outcome: 'Vault Access Attempted',
          eval: 'Correct',
          badge: 'bg-primary/10 text-primary'
        },
        {
          time: '08:31:40',
          campaign: 'PX-9810',
          stage: 'Initial Discovery',
          target: 'WORKSTATION-902',
          prob: '64%',
          outcome: 'Disrupted via Quarantine',
          eval: 'Partial',
          badge: 'bg-secondary-container/20 text-secondary'
        },
        {
          time: '07:15:22',
          campaign: 'PX-9804',
          stage: 'Persistence',
          target: 'CLOUD-IAM-ROLE',
          prob: '78%',
          outcome: 'Role Assumed',
          eval: 'Correct',
          badge: 'bg-primary/10 text-primary'
        },
        {
          time: '06:02:18',
          campaign: 'PX-9799',
          stage: 'Lateral Movement',
          target: 'PROD-API-GW',
          prob: '81%',
          outcome: 'Pivoted to legacy subnet (unmonitored)',
          eval: 'Missed',
          badge: 'bg-error-container/20 text-error'
        }
      ]
    };
  }

  getState() {
    return this.state;
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  beginView() {
    if (this._viewUnsub) {
      this._viewUnsub();
      this._viewUnsub = null;
    }
  }

  subscribeView(listener) {
    this.beginView();
    this._viewUnsub = this.subscribe(listener);
    return this._viewUnsub;
  }

  notify() {
    for (const listener of this.listeners) {
      listener(this.state);
    }
  }

  setModule(moduleId) {
    if (this.state.currentModule === moduleId) return;
    this.state.currentModule = moduleId;
    audio.playBlip(720, 0.03);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    this.notify();
  }

  selectCase(caseId) {
    this.state.activeCaseId = caseId;
    audio.playConfirm();
    this.notify();
  }

  setSimulationOption(optionId) {
    this.state.activeSimulationOption = optionId;
    audio.playBlip(880, 0.04);
    this.notify();
  }

  toggleSound() {
    this.state.soundEnabled = audio.toggle();
    if (this.state.soundEnabled) {
      audio.playChirp();
    }
    this.notify();
  }

  openApprovalModal() {
    this.state.approvalModalOpen = true;
    audio.playAlert();
    this.notify();
  }

  closeApprovalModal() {
    this.state.approvalModalOpen = false;
    audio.playBlip(440, 0.03);
    this.notify();
  }

  confirmDefenseApproval() {
    this.state.approvalModalOpen = false;
    this.state.simulationApplied = true;
    
    // Quarantine PC-017
    if (this.state.nodes['PC-017']) {
      this.state.nodes['PC-017'].isolated = true;
      this.state.nodes['PC-017'].status = 'QUARANTINED';
    }

    // Update global metrics to post-disruption state
    this.state.telemetry.overallRisk = 38;
    this.state.telemetry.dbCompromise = 14;

    this.state.approvalTicket = {
      id: 'SEC-9921-ISO',
      target: 'PC-017 (10.4.1.17)',
      approver: 'Col. Marcus Vance (Level 3 SOC Commander)',
      status: 'ENFORCED_IN_PRODUCTION',
      time: new Date().toUTCString(),
      policy: 'IR-402 Policy Compliance'
    };

    // Add new timeline event
    this.state.timeline.unshift({
      id: `ev-${Date.now()}`,
      time: new Date().toISOString().substring(11, 19),
      type: 'DEFENSE',
      badgeClass: 'bg-primary text-on-primary font-bold',
      borderClass: 'bg-primary',
      title: 'DISRUPTION ENFORCED: PC-017 isolated from local network bridge',
      details: 'Kill chain severed at Hop 1. Traversal toward SERVER-03 terminated.',
      icon: 'verified_user',
      actor: 'SOC IR-402 Automated Dispatch',
      target: 'PC-017'
    });

    audio.playQuarantine();
    this.notify();
  }

  quarantineNode(nodeId) {
    if (this.state.nodes[nodeId]) {
      const node = this.state.nodes[nodeId];
      node.isolated = !node.isolated;
      node.status = node.isolated ? 'QUARANTINED' : 'ACTIVE_SENSOR';
      
      if (node.isolated) {
        audio.playQuarantine();
      } else {
        audio.playConfirm();
      }
      this.notify();
    }
  }

  openNodeDetail(nodeId) {
    this.state.selectedNode = this.state.nodes[nodeId] || null;
    this.state.nodeDetailModalOpen = true;
    audio.playBlip(600, 0.04);
    this.notify();
  }

  closeNodeDetail() {
    this.state.nodeDetailModalOpen = false;
    this.state.selectedNode = null;
    audio.playBlip(440, 0.03);
    this.notify();
  }

  setSearchModal(open) {
    this.state.searchModalOpen = open;
    audio.playBlip(open ? 900 : 450, 0.03);
    this.notify();
  }

  setTimelineFilter(filter) {
    this.state.timelineFilter = filter;
    audio.playBlip(800, 0.03);
    this.notify();
  }

  recalibrateGraph() {
    this.state.recalibrating = true;
    audio.playChirp();
    this.notify();

    setTimeout(() => {
      this.state.recalibrating = false;
      this.state.telemetry.epoch += 1;
      this.state.telemetry.avgConfidence = Math.floor(90 + Math.random() * 4);
      audio.playConfirm();
      this.notify();
    }, 1200);
  }

  forceRetrain() {
    this.state.retraining = true;
    audio.playAlert();
    this.notify();

    setTimeout(() => {
      this.state.retraining = false;
      this.state.telemetry.lossL1 = (0.038 + Math.random() * 0.005).toFixed(4);
      this.state.telemetry.ece = 0.029;
      audio.playConfirm();
      this.notify();
    }, 1800);
  }

  updateEPS() {
    const delta = Math.floor(Math.random() * 400) - 200;
    this.state.telemetry.eps = Math.max(41000, Math.min(44500, this.state.telemetry.eps + delta));
    this.notify();
  }
}

export const store = new Store();
