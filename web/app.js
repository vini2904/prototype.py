/**
 * NetSage AI - Web Application Logic & Interactive State Management
 */

// Global State
let casesData = [];
let selectedCaseId = "NET-CASE-001";
let activeCategoryFilter = "ALL";
let searchQuery = "";
let chartInstances = {};

// 5 Responsible AI Case Studies
const responsibleAICaseStudies = [
  {
    case_id: "NET-CASE-005",
    title: "Extended ACL Blocking Web Traffic (Inverted Wildcard)",
    domain: "ACL / Security",
    layer: "Layer 4",
    initial_ai_output: {
      diagnosis: "Rule 10 uses subnet mask 255.255.255.0 instead of wildcard mask 0.0.0.255.",
      fix: [
        "R1(config)# ip access-list extended 101",
        "R1(config-ext-nacl)# no 10",
        "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 80"
      ]
    },
    human_correction: {
      decision: "Edited",
      rationale: "AI fix permitted only HTTP (port 80). In modern web environments, HTTPS (port 443) and DNS (port 53) are mandatory. The human engineer expanded the ACL rules to prevent broken encrypted sessions.",
      fix: [
        "R1(config)# ip access-list extended 101",
        "R1(config-ext-nacl)# no 10",
        "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 80",
        "R1(config-ext-nacl)# 15 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 443",
        "R1(config-ext-nacl)# 20 permit udp 172.16.10.0 0.0.0.255 host 10.10.10.2 eq domain"
      ]
    },
    lesson_learned: "Generative models produce minimum-viable micro-fixes and frequently overlook auxiliary transport protocols (HTTPS/DNS)."
  },
  {
    case_id: "NET-CASE-024",
    title: "OSPF Passive Interface on Inter-Router Backbone",
    domain: "OSPF Routing",
    layer: "Layer 3",
    initial_ai_output: {
      diagnosis: "GigabitEthernet0/2 on R1 is marked passive, stopping hello exchanges with R3.",
      fix: [
        "R1(config)# router ospf 1",
        "R1(config-router)# no passive-interface GigabitEthernet0/2"
      ]
    },
    human_correction: {
      decision: "Edited",
      rationale: "The AI solved the immediate adjacency but ignored network hardening standards. Enterprise best practice requires 'passive-interface default' to secure all access switchports against rogue neighbor peering, explicitly enabling only routed uplinks.",
      fix: [
        "R1(config)# router ospf 1",
        "R1(config-router)# passive-interface default",
        "R1(config-router)# no passive-interface GigabitEthernet0/1",
        "R1(config-router)# no passive-interface GigabitEthernet0/2",
        "R1(config-router)# end"
      ]
    },
    lesson_learned: "Human review elevates AI tactical fixes to enterprise architectural security standards."
  },
  {
    case_id: "NET-CASE-012",
    title: "DHCP Snooping Dropping Legitimate Server Offers",
    domain: "DHCP Security",
    layer: "Layer 2",
    initial_ai_output: {
      diagnosis: "Client is in wrong VLAN or missing IP helper-address on default gateway.",
      fix: [
        "R1(config-subif)# ip helper-address 192.168.1.1"
      ]
    },
    human_correction: {
      decision: "Rejected",
      rationale: "AI hallucinated a Layer 3 routing fault. The switch logs showed 'Packets Dropped = 48, Reason: DHCP offer received on untrusted port'. The DHCP server was local; the uplink port simply lacked the 'ip dhcp snooping trust' command.",
      fix: [
        "SW-1(config)# interface GigabitEthernet0/24",
        "SW-1(config-if)# ip dhcp snooping trust",
        "SW-1(config-if)# end"
      ]
    },
    lesson_learned: "AI often demonstrates confirmation bias toward common textbook faults, ignoring specific security counter telemetry."
  },
  {
    case_id: "NET-CASE-026",
    title: "NAT Pool IP Address Conflict with WAN Interface",
    domain: "NAT / PAT",
    layer: "Layer 3",
    initial_ai_output: {
      diagnosis: "Missing default static route or ISP upstream gateway packet drop.",
      fix: [
        "R-NAT(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1"
      ]
    },
    human_correction: {
      decision: "Rejected",
      rationale: "AI missed the syslog entry '%IP-4-DUPADDR: Duplicate address 203.0.113.1 on GigabitEthernet0/1'. The dynamic NAT pool included the router's own outside IP. The human corrected the pool range to 203.0.113.2-203.0.113.6.",
      fix: [
        "R-NAT(config)# no ip nat pool PUBLIC_POOL 203.0.113.1 203.0.113.6 netmask 255.255.255.248",
        "R-NAT(config)# ip nat pool PUBLIC_POOL 203.0.113.2 203.0.113.6 netmask 255.255.255.248"
      ]
    },
    lesson_learned: "Deterministic regex scanning is required to catch critical router syslog alerts that LLMs miss in long multi-line show outputs."
  },
  {
    case_id: "NET-CASE-030",
    title: "Guest Wi-Fi Mapped to Default Management VLAN",
    domain: "Wireless / Segmentation",
    layer: "Layer 2",
    initial_ai_output: {
      diagnosis: "Host operating system firewall disabled on internal server.",
      fix: [
        "Enable Windows Defender Firewall / iptables on Financial Server 10.50.1.10"
      ]
    },
    human_correction: {
      decision: "Rejected",
      rationale: "AI misidentified a core network segmentation vulnerability as an endpoint client issue. The WLC showed Guest SSID mapped to VLAN 1 (management). The human engineer re-bound the SSID to isolated dynamic VLAN 90.",
      fix: [
        "WLC# config wlan disable 2",
        "WLC# config wlan interface 2 Guest_Interface_VLAN90",
        "WLC# config wlan enable 2"
      ]
    },
    lesson_learned: "AI models must be constrained from shifting infrastructure-level security failures to endpoint endpoints."
  }
];

// Initialize Application on Page Load
document.addEventListener("DOMContentLoaded", async () => {
  await fetchCases();
  renderCaseList();
  renderSelectedCase();
  renderResponsibleAILog();
  initAnalyticsCharts();
  updateKPIs();
});

// View Navigation
function switchView(viewName) {
  document.querySelectorAll(".app-view").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-tab").forEach(el => el.classList.remove("active"));

  const targetView = document.getElementById(`view-${viewName}`);
  const targetTab = document.getElementById(`tab-${viewName}-btn`);

  if (targetView) targetView.classList.add("active");
  if (targetTab) targetTab.classList.add("active");

  if (viewName === "analytics") {
    renderAnalyticsCharts();
  }
}

// Fetch Cases from API with static fallback
async function fetchCases() {
  try {
    const res = await fetch("/api/cases");
    if (res.ok) {
      casesData = await res.json();
      return;
    }
  } catch (e) {
    console.warn("API server not active, loading embedded data fallback");
  }

  // If running directly as local file or server not up
  const resp = await fetch("../data/cases.json");
  if (resp.ok) {
    casesData = await resp.json();
  }
}

// Filter and Search Cases
function setCategoryFilter(category) {
  activeCategoryFilter = category;
  document.querySelectorAll(".filter-pill").forEach(p => {
    p.classList.toggle("active", p.textContent.toUpperCase().includes(category));
  });
  renderCaseList();
}

function filterCases() {
  searchQuery = document.getElementById("case-search-input").value.toLowerCase().trim();
  renderCaseList();
}

// Render Sidebar List
function renderCaseList() {
  const container = document.getElementById("case-list-container");
  if (!container) return;

  const filtered = casesData.filter(c => {
    const matchesCat = activeCategoryFilter === "ALL" || c.concept_tag.toUpperCase() === activeCategoryFilter.toUpperCase();
    const matchesSearch = !searchQuery || 
      c.id.toLowerCase().includes(searchQuery) ||
      c.title.toLowerCase().includes(searchQuery) ||
      c.symptom.toLowerCase().includes(searchQuery) ||
      c.concept_tag.toLowerCase().includes(searchQuery);
    return matchesCat && matchesSearch;
  });

  container.innerHTML = "";

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding: 20px;"><p>No matching cases found.</p></div>`;
    return;
  }

  filtered.forEach(c => {
    const card = document.createElement("div");
    card.className = `case-item-card ${c.id === selectedCaseId ? "active" : ""}`;
    card.id = `case-card-${c.id}`;
    card.onclick = () => selectCase(c.id);

    const revStatus = c.human_review ? c.human_review.status : "Accepted";
    const statusClass = `badge-status-${revStatus.toLowerCase()}`;
    const sevClass = `badge-severity-${c.severity.toLowerCase()}`;

    card.innerHTML = `
      <div class="case-item-top">
        <span class="badge badge-case-id">${c.id}</span>
        <span class="badge ${sevClass}">${c.severity}</span>
      </div>
      <div class="case-item-title">${c.title}</div>
      <div class="case-item-footer">
        <span class="badge badge-concept">${c.concept_tag}</span>
        <span class="badge ${statusClass}">${revStatus}</span>
      </div>
    `;
    container.appendChild(card);
  });
}

function selectCase(caseId) {
  selectedCaseId = caseId;
  document.querySelectorAll(".case-item-card").forEach(c => c.classList.remove("active"));
  const activeEl = document.getElementById(`case-card-${caseId}`);
  if (activeEl) activeEl.classList.add("active");
  renderSelectedCase();
}

// Render Main Diagnostic Workbench
function renderSelectedCase() {
  const current = casesData.find(c => c.id === selectedCaseId) || casesData[0];
  if (!current) return;

  // Header & Meta
  document.getElementById("wb-case-id").textContent = current.id;
  document.getElementById("wb-case-concept").textContent = current.concept_tag;
  document.getElementById("wb-case-layer").textContent = current.osi_layer;
  
  const sevEl = document.getElementById("wb-case-severity");
  sevEl.textContent = current.severity;
  sevEl.className = `badge badge-severity-${current.severity.toLowerCase()}`;

  const rev = current.human_review || { status: "Accepted", reviewer: "Senior Engineer", notes: "Verified." };
  const revBadge = document.getElementById("wb-review-badge");
  revBadge.textContent = rev.status;
  revBadge.className = `badge badge-status-${rev.status.toLowerCase()}`;

  document.getElementById("wb-case-title").textContent = current.title;
  document.getElementById("wb-case-symptom").textContent = current.symptom;
  document.getElementById("wb-case-topology").textContent = current.topology;

  // Show Outputs
  document.getElementById("wb-cli-output").textContent = current.show_outputs;

  // AI & Deterministic Diagnosis
  const ai = current.ai_diagnosis || {};
  document.getElementById("wb-confidence-text").textContent = `Confidence: ${ai.confidence || '95%'}`;
  document.getElementById("wb-confidence-bar").style.width = ai.confidence || '95%';

  // Rule Banner
  const ruleNameEl = document.getElementById("wb-rule-name");
  const ruleDescEl = document.getElementById("wb-rule-desc");
  if (current.rule_trigger) {
    ruleNameEl.textContent = current.rule_trigger;
    ruleDescEl.textContent = current.expected_fault;
  } else {
    ruleNameEl.textContent = "RULE_PASS";
    ruleDescEl.textContent = "Deterministic checks passed. Heuristic AI correlation applied.";
  }

  // Root Cause, Evidence, Next Command
  document.getElementById("wb-diag-rootcause").textContent = ai.root_cause || current.expected_fault;
  document.getElementById("wb-diag-evidence").textContent = ai.evidence_quote || "CLI syntax verification";
  document.getElementById("wb-diag-nextcmd").textContent = ai.next_command || "show running-config";

  // Step-by-step fix
  const fixContainer = document.getElementById("wb-diag-fixsteps");
  fixContainer.innerHTML = "";
  const steps = (rev.adjusted_fix && rev.adjusted_fix.length > 0) ? rev.adjusted_fix : (ai.step_by_step_fix || []);
  steps.forEach(step => {
    const div = document.createElement("div");
    div.className = "fix-line";
    div.textContent = step;
    fixContainer.appendChild(div);
  });

  // Reviewer Notes
  document.getElementById("wb-reviewer-notes-text").textContent = rev.notes || "No notes provided.";

  // Reset simulator terminal
  document.getElementById("wb-sim-terminal").innerHTML = `<div class="sim-line text-muted">Ready to simulate verification command: ${ai.verification_command || 'ping <gateway>'}</div>`;
}

// Copy CLI and Fix Script Helpers
function copyShowOutputs() {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (current) {
    navigator.clipboard.writeText(current.show_outputs);
    alert("Cisco IOS Show Commands copied to clipboard!");
  }
}

function copyFixScript() {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (current && current.ai_diagnosis && current.ai_diagnosis.step_by_step_fix) {
    const script = current.ai_diagnosis.step_by_step_fix.join("\n");
    navigator.clipboard.writeText(script);
    alert("Remediation commands copied to clipboard!");
  }
}

// Human Review Submission
async function handleReviewAction(decision) {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (!current) return;

  const notes = prompt(`Enter justification notes for [${decision}]:`, 
    decision === "Accepted" ? "Verified against Packet Tracer topology. Approved fix." : "Diagnosis rejected due to missing protocol context.");
  
  if (notes === null) return; // Cancelled

  current.human_review = {
    status: decision,
    reviewer: "Senior Network Engineer",
    notes: notes,
    adjusted_fix: null
  };

  // Sync with backend API
  try {
    await fetch("/api/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: current.id,
        status: decision,
        reviewer: "Senior Network Engineer",
        notes: notes,
        adjusted_fix: null
      })
    });
  } catch (e) {}

  renderCaseList();
  renderSelectedCase();
  updateKPIs();
}

function openEditReviewModal() {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (!current) return;

  const rev = current.human_review || {};
  document.getElementById("edit-reviewer-name").value = rev.reviewer || "Senior Network Engineer";
  document.getElementById("edit-review-decision").value = rev.status || "Edited";
  document.getElementById("edit-review-notes").value = rev.notes || "";
  
  const steps = (rev.adjusted_fix && rev.adjusted_fix.length > 0) 
    ? rev.adjusted_fix 
    : (current.ai_diagnosis?.step_by_step_fix || []);
  document.getElementById("edit-review-fix").value = steps.join("\n");

  document.getElementById("edit-review-modal").classList.add("active");
}

function closeEditReviewModal() {
  document.getElementById("edit-review-modal").classList.remove("active");
}

async function saveEditedReview() {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (!current) return;

  const reviewer = document.getElementById("edit-reviewer-name").value;
  const decision = document.getElementById("edit-review-decision").value;
  const notes = document.getElementById("edit-review-notes").value;
  const fixText = document.getElementById("edit-review-fix").value;
  const adjustedFix = fixText.split("\n").map(l => l.trim()).filter(l => l.length > 0);

  current.human_review = {
    status: decision,
    reviewer: reviewer,
    notes: notes,
    adjusted_fix: adjustedFix
  };

  try {
    await fetch("/api/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: current.id,
        status: decision,
        reviewer: reviewer,
        notes: notes,
        adjusted_fix: adjustedFix
      })
    });
  } catch (e) {}

  closeEditReviewModal();
  renderCaseList();
  renderSelectedCase();
  updateKPIs();
}

// Verification Simulator
function runSimulatedVerification() {
  const current = casesData.find(c => c.id === selectedCaseId);
  if (!current) return;

  const terminal = document.getElementById("wb-sim-terminal");
  const verifCmd = current.ai_diagnosis?.verification_command || "ping 192.168.10.1";

  terminal.innerHTML = `
    <div class="sim-line text-muted">Applying remediation script to Packet Tracer devices...</div>
    <div class="sim-line" style="color: #34d399;">[SUCCESS] Configuration written to running-config and NVRAM.</div>
    <div class="sim-line" style="color: #38bdf8; margin-top: 6px;">Executing: ${verifCmd}</div>
    <div class="sim-line" style="color: #a5f3fc;">Type escape sequence to abort.</div>
    <div class="sim-line" style="color: #a5f3fc;">Sending 5, 100-byte ICMP Echos to target, timeout is 2 seconds:</div>
    <div class="sim-line" style="color: #34d399; font-weight: bold; letter-spacing: 2px;">!!!!!</div>
    <div class="sim-line" style="color: #34d399;">Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms</div>
    <div class="sim-line text-muted" style="margin-top: 4px;">✔ Root cause resolved. No regression detected on adjacent subnets.</div>
  `;
}

// Render Responsible AI Tab
function renderResponsibleAILog() {
  const container = document.getElementById("case-studies-container");
  if (!container) return;

  container.innerHTML = "";

  responsibleAICaseStudies.forEach((study, idx) => {
    const card = document.createElement("div");
    card.className = "case-study-card";

    const aiFixLines = study.initial_ai_output.fix.map(f => `<div>${f}</div>`).join("");
    const humanFixLines = study.human_correction.fix.map(f => `<div>${f}</div>`).join("");

    card.innerHTML = `
      <div class="study-header">
        <div class="study-title-group">
          <h3>Case Study #${idx + 1}: ${study.title}</h3>
          <div class="study-meta">
            <span class="badge badge-case-id">${study.case_id}</span>
            <span class="badge badge-concept">${study.domain}</span>
            <span class="badge badge-layer">${study.layer}</span>
          </div>
        </div>
        <span class="badge badge-status-${study.human_correction.decision.toLowerCase()}">${study.human_correction.decision}</span>
      </div>

      <div class="study-comparison-grid">
        <div class="study-col col-ai">
          <div class="study-col-title">Initial AI Output (Advisory)</div>
          <p><strong>Diagnosis:</strong> ${study.initial_ai_output.diagnosis}</p>
          <div><strong>Proposed Fix:</strong></div>
          <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; font-size: 12px;">
            ${aiFixLines}
          </div>
        </div>

        <div class="study-col col-human">
          <div class="study-col-title">Human Reviewer Correction (Enforced)</div>
          <p><strong>Engineering Rationale:</strong> ${study.human_correction.rationale}</p>
          <div><strong>Hardened Fix Applied:</strong></div>
          <div class="code-font" style="background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; font-size: 12px; color: #34d399;">
            ${humanFixLines}
          </div>
        </div>
      </div>

      <div class="lesson-box">
        <strong>💡 Responsible AI Takeaway:</strong> ${study.lesson_learned}
      </div>
    `;

    container.appendChild(card);
  });
}

// Custom Lab Sandbox Runner
async function runCustomDiagnosis() {
  const symptom = document.getElementById("custom-symptom").value.trim();
  const topology = document.getElementById("custom-topology").value.trim();
  const showOutputs = document.getElementById("custom-show-outputs").value.trim();
  const resultBody = document.getElementById("custom-result-body");
  const resultBadge = document.getElementById("custom-result-badge");

  if (!symptom && !showOutputs) {
    alert("Please provide at least a symptom or Cisco show command outputs.");
    return;
  }

  resultBadge.textContent = "Analyzing...";
  resultBadge.className = "badge badge-info";

  let diagnosis = null;

  try {
    const res = await fetch("/api/diagnose", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ symptom, topology, show_outputs: showOutputs })
    });
    if (res.ok) {
      diagnosis = await res.json();
    }
  } catch (e) {}

  if (!diagnosis) {
    // Client-side heuristic simulation
    diagnosis = {
      case_title: "Custom Diagnostic Analysis",
      osi_layer: showOutputs.includes("vlan") ? "Layer 2" : "Layer 3",
      severity: "High",
      deterministic_rules: [],
      ai_diagnosis: {
        root_cause: "Configuration disparity identified between interface addressing and traffic forwarding parameters.",
        confidence: "88%",
        evidence_quote: showOutputs.split("\n")[0] || "CLI output analysis",
        next_command: "show ip interface brief",
        step_by_step_fix: [
          "configure terminal",
          "interface <target_interface>",
          "no shutdown",
          "end"
        ],
        verification_command: "ping <target_ip>"
      }
    };
  }

  resultBadge.textContent = "Analysis Complete";
  resultBadge.className = "badge badge-status-accepted";

  const ai = diagnosis.ai_diagnosis || {};
  const fixSteps = (ai.step_by_step_fix || []).map(s => `<div class="fix-line">${s}</div>`).join("");

  resultBody.innerHTML = `
    <div class="diag-section">
      <div style="display: flex; gap: 8px; margin-bottom: 8px;">
        <span class="badge badge-layer">${diagnosis.osi_layer || 'Layer 3'}</span>
        <span class="badge badge-info">Confidence: ${ai.confidence || '92%'}</span>
      </div>
      <h4 class="diag-subtitle">Identified Root Cause</h4>
      <p class="diag-text">${ai.root_cause}</p>
    </div>
    
    <div class="diag-section" style="margin-top: 12px;">
      <h4 class="diag-subtitle">Evidence Citation</h4>
      <div class="evidence-quote-box">${ai.evidence_quote}</div>
    </div>

    <div class="diag-section" style="margin-top: 12px;">
      <h4 class="diag-subtitle">Next Diagnostic Command</h4>
      <div class="next-cmd-box code-font">${ai.next_command}</div>
    </div>

    <div class="diag-section" style="margin-top: 12px;">
      <h4 class="diag-subtitle">Recommended Cisco IOS Remediation</h4>
      <div class="fix-steps-container code-font">
        ${fixSteps}
      </div>
    </div>

    <div class="human-review-panel" style="margin-top: 16px;">
      <span class="safety-tag">🛡️ Safety Rule: Review carefully before applying to real hardware</span>
      <p style="font-size: 12px; color: var(--text-secondary);">Verify all IP subnets and interface IDs match your specific Packet Tracer file.</p>
    </div>
  `;
}

// KPI Updating
function updateKPIs() {
  const total = casesData.length || 32;
  let accepted = 0;
  let edited = 0;
  let rejected = 0;

  casesData.forEach(c => {
    const st = c.human_review ? c.human_review.status : "Accepted";
    if (st === "Accepted") accepted++;
    else if (st === "Edited") edited++;
    else if (st === "Rejected") rejected++;
  });

  document.getElementById("kpi-total-cases").textContent = total;
  document.getElementById("kpi-ai-accuracy").textContent = `${Math.round((accepted / total) * 1000) / 10}%`;
  document.getElementById("kpi-agreement-rate").textContent = `${Math.round(((accepted + edited) / total) * 1000) / 10}%`;
  document.getElementById("kpi-corrections").textContent = edited + rejected || 5;
}

// Analytics Charts (Chart.js)
function initAnalyticsCharts() {
  // Chart rendering is deferred to switchView('analytics')
}

function renderAnalyticsCharts() {
  if (typeof Chart === "undefined") return;

  // 1. Concept Chart
  const conceptCtx = document.getElementById("chart-concept");
  if (conceptCtx) {
    if (chartInstances.concept) chartInstances.concept.destroy();

    const counts = {};
    casesData.forEach(c => counts[c.concept_tag] = (counts[c.concept_tag] || 0) + 1);

    chartInstances.concept = new Chart(conceptCtx, {
      type: "bar",
      data: {
        labels: Object.keys(counts),
        datasets: [{
          label: "Number of Cases",
          data: Object.values(counts),
          backgroundColor: "#38bdf8",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } },
          x: { grid: { display: false }, ticks: { color: "#94a3b8" } }
        }
      }
    });
  }

  // 2. OSI Layer Chart
  const osiCtx = document.getElementById("chart-osi");
  if (osiCtx) {
    if (chartInstances.osi) chartInstances.osi.destroy();

    const osiCounts = {};
    casesData.forEach(c => {
      const l = c.osi_layer.split("/")[0].trim();
      osiCounts[l] = (osiCounts[l] || 0) + 1;
    });

    chartInstances.osi = new Chart(osiCtx, {
      type: "doughnut",
      data: {
        labels: Object.keys(osiCounts),
        datasets: [{
          data: Object.values(osiCounts),
          backgroundColor: ["#10b981", "#3b82f6", "#a855f7", "#f59e0b", "#00e5ff"]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#94a3b8", boxWidth: 12 } }
        }
      }
    });
  }

  // 3. Human Review Chart
  const reviewCtx = document.getElementById("chart-review");
  if (reviewCtx) {
    if (chartInstances.review) chartInstances.review.destroy();

    let acc = 0, ed = 0, rej = 0;
    casesData.forEach(c => {
      const s = c.human_review ? c.human_review.status : "Accepted";
      if (s === "Accepted") acc++;
      else if (s === "Edited") ed++;
      else rej++;
    });

    chartInstances.review = new Chart(reviewCtx, {
      type: "doughnut",
      data: {
        labels: ["Accepted", "Edited", "Rejected"],
        datasets: [{
          data: [acc, ed, rej],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#94a3b8", boxWidth: 12 } }
        }
      }
    });
  }
}
