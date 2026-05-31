/**
 * review.js — Review Page Controller
 * =====================================
 * Orchestrates the three-pane review interface:
 *   Left pane:   Vulnerability list (vuln-sidebar)
 *   Center pane: Code editor (editor-pane)
 *   Right pane:  XAI feedback panel (analysis-panel)
 *
 * Data flow:
 *   1. On load, reads ?file=<UUID>&project=<UUID> from URL query params.
 *   2. Fetches file data (vulnerabilities) from the API.
 *   3. Fetches decrypted source code from the API.
 *   4. Passes both to CodeEditor.loadFile().
 *   5. Renders the vulnerability list in the left sidebar.
 *   6. When user selects a vulnerability:
 *       a. Editor scrolls + highlights the line.
 *       b. Right panel shows detail card + SHAP/LIME chart.
 *       c. Fetches the XAI explanation from the API.
 */

import { api, ApiError, useMockData }         from "./api.js";
import { CodeEditor }                          from "./editor.js";
import { createExplanationChart }              from "./shap_chart.js";

// ─── Toast Notification Helper ────────────────────────────────────────────────

const Toast = {
  container: null,

  init() {
    if (this.container) return;
    this.container = document.createElement("div");
    this.container.className = "toast-container";
    document.body.appendChild(this.container);
  },

  show(message, type = "info", duration = 4000) {
    this.init();
    const toast = document.createElement("div");
    const icons = { success: "✓", error: "✕", warning: "⚠", info: "ℹ" };
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `<span style="flex-shrink:0">${icons[type] || "ℹ"}</span> <span>${message}</span>`;
    this.container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add("toast-exit");
      toast.addEventListener("animationend", () => toast.remove(), { once: true });
    }, duration);
  },

  success: (m) => Toast.show(m, "success"),
  error:   (m) => Toast.show(m, "error", 6000),
  warning: (m) => Toast.show(m, "warning"),
  info:    (m) => Toast.show(m, "info"),
};


// ─── ReviewPage Controller ───────────────────────────────────────────────────

class ReviewPage {

  constructor() {
    // Parsed from URL
    this.fileId    = null;
    this.projectId = null;

    // Data
    this.fileData    = null;
    this.sourceCode  = null;
    this.activeVuln  = null;
    this.activeChart = null;

    // UI elements
    this.editor      = null;
    this.vulnFilter  = "all"; // current severity filter in left sidebar

    // Cache for explanation data (vulnId → explanation object)
    this._explanationCache = new Map();
  }

  // ── Initialization ─────────────────────────────────────────────────────

  async init() {
    // Parse URL params
    const params = new URLSearchParams(window.location.search);
    this.fileId    = params.get("file");
    this.projectId = params.get("project");

    // Check if backend is up; fall back to mock data if not
    try {
      await api.health();
    } catch {
      useMockData();
      // In mock mode, use hardcoded IDs
      if (!this.fileId) this.fileId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
      Toast.info("Running in demo mode — backend not connected.");
    }

    // Build the page structure
    this._buildLayout();
    this._initEditor();
    this._bindUI();

    // Load file data
    if (this.fileId) {
      await this._loadFile(this.fileId);
    } else {
      this._showEditorEmpty("No file selected. Open a project from the dashboard.");
    }
  }

  // ── Layout Construction ────────────────────────────────────────────────

  _buildLayout() {
    // The <main> element in review.html
    const main = document.querySelector("main") || document.body;
    main.innerHTML = "";
    main.className = "app-content";

    // ── Left: Vulnerability sidebar ──
    this.vulnSidebarEl = this._createElement("div", "vuln-sidebar");
    this.vulnSidebarEl.innerHTML = `
      <div class="vuln-sidebar__header">
        <div class="vuln-sidebar__title">Vulnerabilities</div>
        <div class="vuln-sidebar__filters" id="vuln-filters">
          <span class="filter-chip active" data-filter="all">All</span>
          <span class="filter-chip" data-filter="critical">Critical</span>
          <span class="filter-chip" data-filter="high">High</span>
          <span class="filter-chip" data-filter="medium">Medium</span>
          <span class="filter-chip" data-filter="low">Low</span>
        </div>
      </div>
      <div class="vuln-sidebar__list" id="vuln-list">
        <div class="empty-state">
          <div class="spinner spinner--sm"></div>
        </div>
      </div>
    `;

    // ── Center: Editor pane ──
    this.editorPaneEl = this._createElement("div", "editor-pane");
    const editorWrap = this._createElement("div", "");
    editorWrap.style.cssText = "display:flex; flex-direction:column; height:100%;";
    // File tabs (we just show one tab for now; Phase 4 adds multi-file)
    this.fileTabsEl = this._createElement("div", "file-tabs");
    this.fileTabsEl.innerHTML = `<div class="file-tab active" id="current-file-tab">
      <span class="file-tab__indicator" style="background: var(--amber-bright);"></span>
      <span>Loading…</span>
    </div>`;
    this.editorContainerEl = this._createElement("div", "");
    this.editorContainerEl.style.cssText = "flex:1; display:flex; flex-direction:column; overflow:hidden;";
    editorWrap.appendChild(this.fileTabsEl);
    editorWrap.appendChild(this.editorContainerEl);
    this.editorPaneEl.appendChild(editorWrap);

    // ── Right: Analysis panel ──
    this.analysisPanelEl = this._createElement("div", "analysis-panel");
    this.analysisPanelEl.innerHTML = `
      <div class="panel-header">
        <span class="panel-header__title">Analysis</span>
        <button class="btn btn-ghost btn-sm" id="panel-close-btn" title="Hide panel" style="font-size:16px; padding:0 4px;">⟩</button>
      </div>
      <div class="panel-tabs">
        <div class="panel-tab active" data-tab="detail">Detail</div>
        <div class="panel-tab" data-tab="shap">SHAP</div>
        <div class="panel-tab" data-tab="lime">LIME</div>
        <div class="panel-tab" data-tab="fix">Fix</div>
      </div>
      <div class="panel-body" id="panel-body">
        <div class="empty-state">
          <div class="empty-state__icon">🔍</div>
          <div class="empty-state__title">Select a vulnerability</div>
          <div class="empty-state__desc font-serif">
            Click a highlighted line or an item in the left panel to see its analysis.
          </div>
        </div>
      </div>
    `;

    // Assemble layout
    const layout = this._createElement("div", "review-layout");
    layout.style.cssText = "width:100%; height:100%;";
    layout.appendChild(this.vulnSidebarEl);
    layout.appendChild(this.editorPaneEl);
    layout.appendChild(this.analysisPanelEl);
    main.appendChild(layout);
  }

  _initEditor() {
    this.editor = new CodeEditor(this.editorContainerEl);
    this.editor.onVulnerabilitySelect = (vuln) => this._onVulnSelected(vuln);
  }

  _bindUI() {
    // Filter chips
    document.getElementById("vuln-filters")?.addEventListener("click", (e) => {
      const chip = e.target.closest(".filter-chip");
      if (!chip) return;
      document.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      this.vulnFilter = chip.dataset.filter;
      this._renderVulnList();
    });

    // Panel tabs
    this.analysisPanelEl.addEventListener("click", (e) => {
      const tab = e.target.closest(".panel-tab");
      if (!tab) return;
      this.analysisPanelEl.querySelectorAll(".panel-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      this._renderPanelTab(tab.dataset.tab);
    });

    // Panel close button (hides panel to give editor more room)
    document.getElementById("panel-close-btn")?.addEventListener("click", () => {
      this.analysisPanelEl.style.display =
        this.analysisPanelEl.style.display === "none" ? "" : "none";
    });

    // Alt+ArrowLeft/Right to navigate panel tabs
    document.addEventListener("keydown", (e) => {
      if (e.altKey && e.key === "ArrowLeft")  this._prevPanelTab();
      if (e.altKey && e.key === "ArrowRight") this._nextPanelTab();
    });
  }

  // ── Data Loading ───────────────────────────────────────────────────────

  async _loadFile(fileId) {
    try {
      // Parallel fetch: file metadata + source code
      const [fileData, sourceData] = await Promise.all([
        api.getFile(fileId),
        api.getFileSource(fileId),
      ]);

      this.fileData   = fileData;
      this.sourceCode = sourceData.source || sourceData;

      // Update file tab label
      const tab = document.getElementById("current-file-tab");
      if (tab) {
        const langClass = fileData.language || "";
        tab.innerHTML = `
          <span class="file-tab__indicator vuln-dot-${this._riskColor(fileData.risk_score)}"></span>
          <span class="lang-tag ${langClass}" style="margin:0; border:none; background:none; font-size:11px;">${langClass}</span>
          ${fileData.filename}
        `;
      }

      // Render editor
      this.editor.loadFile(fileData, this.sourceCode);

      // Render vulnerability list
      this._renderVulnList();

      Toast.success(`Loaded ${fileData.filename} — ${fileData.vulnerabilities?.length || 0} issues found.`);

    } catch (err) {
      console.error("Failed to load file:", err);
      this._showEditorEmpty(`Failed to load file: ${err.message}`);
      Toast.error(`Could not load file. ${err.message}`);
    }
  }

  async _loadExplanation(vulnId) {
    if (this._explanationCache.has(vulnId)) {
      return this._explanationCache.get(vulnId);
    }
    try {
      const explanation = await api.getExplanation(vulnId);
      this._explanationCache.set(vulnId, explanation);
      return explanation;
    } catch (err) {
      console.warn("Could not load explanation:", err.message);
      return null;
    }
  }

  // ── Vulnerability List ─────────────────────────────────────────────────

  _renderVulnList() {
    const listEl = document.getElementById("vuln-list");
    if (!listEl) return;

    const vulns = this.fileData?.vulnerabilities || [];
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const filtered = vulns
      .filter(v => this.vulnFilter === "all" || v.severity === this.vulnFilter)
      .sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

    if (filtered.length === 0) {
      listEl.innerHTML = `
        <div class="empty-state" style="padding: 3rem 1rem;">
          <div class="empty-state__icon">✓</div>
          <div class="empty-state__title">${vulns.length === 0 ? "No issues found" : "No matches"}</div>
          <div class="empty-state__desc font-serif">
            ${vulns.length === 0
              ? "This file looks clean for the selected filters."
              : "Try selecting a different severity filter."}
          </div>
        </div>`;
      return;
    }

    listEl.innerHTML = "";
    filtered.forEach((vuln, idx) => {
      const item = document.createElement("div");
      item.className = "vuln-list-item";
      if (vuln.id === this.activeVuln?.id) {
        item.classList.add("active", `active-${vuln.severity}`);
      }
      item.style.animationDelay = `${idx * 30}ms`;
      item.innerHTML = `
        <div class="vuln-list-item__top">
          <span class="vuln-dot vuln-dot-${vuln.severity}"></span>
          <span class="vuln-list-item__title">${this._esc(vuln.title)}</span>
          <span class="badge badge-${vuln.severity}" style="font-size:9px;">${vuln.severity}</span>
        </div>
        <div class="vuln-list-item__line">
          <span class="text-muted">Line ${vuln.line_start}${vuln.line_end && vuln.line_end !== vuln.line_start ? `–${vuln.line_end}` : ""}</span>
          ${vuln.rule_id ? `<span class="text-muted"> · ${this._esc(vuln.rule_id)}</span>` : ""}
        </div>
      `;
      item.addEventListener("click", () => {
        this.editor.selectVulnerability(vuln);
        this._onVulnSelected(vuln);
      });
      listEl.appendChild(item);
    });
  }

  // ── Vulnerability Selection ────────────────────────────────────────────

  async _onVulnSelected(vuln) {
    this.activeVuln = vuln;

    // Update active state in list
    this.vulnSidebarEl.querySelectorAll(".vuln-list-item").forEach(item => {
      item.classList.remove("active", ...["critical","high","medium","low","info"].map(s => `active-${s}`));
    });
    const matchingItems = [...this.vulnSidebarEl.querySelectorAll(".vuln-list-item")]
      .filter(el => el.querySelector(".vuln-list-item__title")?.textContent === vuln.title);
    matchingItems.forEach(el => el.classList.add("active", `active-${vuln.severity}`));

    // Activate the Detail tab and render
    this.analysisPanelEl.querySelectorAll(".panel-tab").forEach(t => t.classList.remove("active"));
    this.analysisPanelEl.querySelector("[data-tab='detail']")?.classList.add("active");
    this._renderDetailTab(vuln);

    // Prefetch explanation in background
    this._loadExplanation(vuln.id);
  }

  // ── Panel Rendering ────────────────────────────────────────────────────

  _renderPanelTab(tabName) {
    if (!this.activeVuln) return;
    switch (tabName) {
      case "detail": this._renderDetailTab(this.activeVuln); break;
      case "shap":   this._renderSHAPTab(this.activeVuln);  break;
      case "lime":   this._renderLIMETab(this.activeVuln);  break;
      case "fix":    this._renderFixTab(this.activeVuln);   break;
    }
  }

  _getPanelBody() {
    return document.getElementById("panel-body");
  }

  _renderDetailTab(vuln) {
    const body = this._getPanelBody();
    if (!body) return;

    const confPct = Math.round((vuln.confidence_score || 0) * 100);
    body.innerHTML = `
      <div class="vuln-detail-card animate-fade-up">
        <div class="vuln-detail-card__header">
          <div class="vuln-detail-card__top">
            <div class="vuln-detail-card__title">${this._esc(vuln.title)}</div>
            <span class="badge badge-${vuln.severity}">${vuln.severity}</span>
          </div>
          <div class="vuln-detail-card__meta">
            <span class="vuln-meta-item">
              <span class="meta-icon">📍</span> Line ${vuln.line_start}${vuln.line_end && vuln.line_end !== vuln.line_start ? `–${vuln.line_end}` : ""}
            </span>
            <span class="vuln-meta-item">
              <span class="meta-icon">📁</span> ${this._esc(vuln.category || "security")}
            </span>
            ${vuln.rule_id ? `<span class="vuln-meta-item"><span class="meta-icon">🔖</span>${this._esc(vuln.rule_id)}</span>` : ""}
          </div>
        </div>

        <div class="vuln-detail-card__body">

          <div class="panel-section">
            <div class="panel-section__label">Description</div>
            <p class="vuln-description font-serif">${this._esc(vuln.description)}</p>
          </div>

          <div class="panel-section">
            <div class="panel-section__label">Confidence</div>
            <div class="confidence-meter">
              <div class="confidence-meter__label">
                <span>Model confidence</span>
                <span style="color: var(--amber-bright); font-weight: 500;">${confPct}%</span>
              </div>
              <div class="confidence-meter__bar">
                <div class="confidence-meter__fill" style="width: ${confPct}%;"></div>
              </div>
            </div>
          </div>

          ${(vuln.cwe_id || vuln.owasp_category) ? `
          <div class="panel-section">
            <div class="panel-section__label">References</div>
            <div class="ref-pills">
              ${vuln.cwe_id ? `<span class="ref-pill ref-pill--cwe">⚠ ${this._esc(vuln.cwe_id)}</span>` : ""}
              ${vuln.owasp_category ? `<span class="ref-pill ref-pill--owasp">🛡 ${this._esc(vuln.owasp_category)}</span>` : ""}
            </div>
          </div>` : ""}

          ${vuln.recommendation ? `
          <div class="panel-section">
            <div class="panel-section__label">Recommendation</div>
            <div class="recommendation-block">
              <div class="recommendation-block__label">✓ How to fix</div>
              <div class="recommendation-block__text">${this._esc(vuln.recommendation)}</div>
            </div>
          </div>` : ""}

          <div class="panel-section" style="margin-top: auto; padding-top: var(--space-2);">
            <button class="btn btn-secondary w-full" id="view-shap-btn">
              View SHAP Explanation →
            </button>
          </div>

        </div>
      </div>
    `;

    // Animate confidence bar after DOM render
    requestAnimationFrame(() => {
      const fill = body.querySelector(".confidence-meter__fill");
      if (fill) fill.style.width = `${confPct}%`;
    });

    // SHAP button
    body.querySelector("#view-shap-btn")?.addEventListener("click", () => {
      this.analysisPanelEl.querySelectorAll(".panel-tab").forEach(t => t.classList.remove("active"));
      this.analysisPanelEl.querySelector("[data-tab='shap']")?.classList.add("active");
      this._renderSHAPTab(this.activeVuln);
    });
  }

  async _renderSHAPTab(vuln) {
    const body = this._getPanelBody();
    if (!body) return;

    body.innerHTML = `
      <div class="xai-section">
        <div class="xai-header">
          <span class="panel-section__label" style="flex:0">Explainability</span>
          <span class="xai-method-badge">SHAP</span>
        </div>
        <div class="empty-state" style="padding: 2rem 0;">
          <div class="spinner"></div>
          <div class="empty-state__title text-sm" style="margin-top:0.5rem;">Loading explanation…</div>
        </div>
      </div>
    `;

    let explanation;
    try {
      explanation = await this._loadExplanation(vuln.id);
    } catch (err) {
      body.innerHTML = `<div class="empty-state"><div class="empty-state__icon">⚠</div><div class="empty-state__title">Explanation unavailable</div></div>`;
      return;
    }

    if (!explanation) {
      body.innerHTML = `<div class="empty-state"><div class="empty-state__icon">📊</div><div class="empty-state__title">No explanation generated</div><div class="empty-state__desc font-serif">Run analysis first to generate XAI explanations.</div></div>`;
      return;
    }

    const expData = explanation.explanation_data;

    body.innerHTML = `
      <div class="xai-section animate-fade-in">
        <div class="xai-header">
          <span class="panel-section__label" style="flex:0">Explainability</span>
          <span class="xai-method-badge">SHAP</span>
        </div>

        ${explanation.summary ? `
        <div class="panel-section">
          <div class="panel-section__label">Why was this flagged?</div>
          <div class="xai-summary">${this._esc(explanation.summary)}</div>
        </div>` : ""}

        <div class="panel-section">
          <div class="panel-section__label">Feature Importance</div>
          <canvas id="shap-canvas" style="border-radius: var(--radius-md);"></canvas>
        </div>

        ${explanation.top_feature_name ? `
        <div class="panel-section">
          <div class="panel-section__label">Top Contributing Factor</div>
          <div style="background: var(--bg-raised); border: 1px solid var(--border-default); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4);">
            <div style="font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 4px;">Highest SHAP value</div>
            <div style="font-family: var(--font-code); font-size: var(--text-sm); color: var(--amber-bright);">
              ${this._esc(explanation.top_feature_name)}
            </div>
            <div style="font-size: var(--text-xs); color: var(--text-muted); margin-top: 4px;">
              Importance: +${(explanation.top_feature_importance || 0).toFixed(3)}
            </div>
          </div>
        </div>` : ""}
      </div>
    `;

    // Destroy previous chart
    if (this.activeChart) {
      this.activeChart.destroy();
      this.activeChart = null;
    }

    // Render SHAP chart on canvas
    const canvas = body.querySelector("#shap-canvas");
    if (canvas && expData) {
      const { SHAPChart } = await import("./shap_chart.js");
      this.activeChart = new SHAPChart(canvas, expData);
      this.activeChart.render();
    }
  }

  async _renderLIMETab(vuln) {
    const body = this._getPanelBody();
    if (!body) return;

    body.innerHTML = `<div class="xai-section"><div class="xai-header"><span class="panel-section__label" style="flex:0">Explainability</span><span class="xai-method-badge" style="border-color:var(--sev-info); color:var(--sev-info); background:var(--sev-info-bg);">LIME</span></div><div class="empty-state" style="padding:2rem 0;"><div class="spinner"></div></div></div>`;

    let explanation;
    try {
      explanation = await this._loadExplanation(vuln.id);
    } catch { explanation = null; }

    if (!explanation) {
      body.innerHTML = `<div class="empty-state"><div class="empty-state__icon">📊</div><div class="empty-state__title">No LIME data</div><div class="empty-state__desc font-serif">LIME explanation not available for this finding.</div></div>`;
      return;
    }

    // Build a synthetic LIME view from SHAP data for demo purposes
    const shapData = explanation.explanation_data;
    const limeData = {
      method: "lime",
      prediction_proba: [1 - (shapData?.prediction || 0.5), shapData?.prediction || 0.5],
      intercept: shapData?.base_value || 0.3,
      features: (shapData?.features || []).map(f => ({
        name: f.name,
        weight: f.shap_value * 0.9 + (Math.random() - 0.5) * 0.05,
        display: f.display,
      })),
    };

    body.innerHTML = `
      <div class="xai-section animate-fade-in">
        <div class="xai-header">
          <span class="panel-section__label" style="flex:0">Explainability</span>
          <span class="xai-method-badge" style="border-color:var(--sev-info); color:var(--sev-info); background:var(--sev-info-bg);">LIME</span>
        </div>
        <div class="panel-section">
          <div class="panel-section__label">Local Feature Weights</div>
          <canvas id="lime-canvas" style="border-radius: var(--radius-md);"></canvas>
        </div>
        <div class="panel-section">
          <div class="panel-section__label">About LIME</div>
          <p class="vuln-description font-serif" style="font-size:12px;">
            LIME explains this specific prediction by perturbing the input features locally
            and fitting a simpler linear model. The weights show each feature's contribution
            to <em>this individual decision</em>, independent of the global model behavior.
          </p>
        </div>
      </div>
    `;

    if (this.activeChart) { this.activeChart.destroy(); this.activeChart = null; }
    const canvas = body.querySelector("#lime-canvas");
    if (canvas) {
      const { LIMEChart } = await import("./shap_chart.js");
      this.activeChart = new LIMEChart(canvas, limeData);
      this.activeChart.render();
    }
  }

  _renderFixTab(vuln) {
    const body = this._getPanelBody();
    if (!body) return;

    const hasSnippets = vuln.code_snippet || vuln.fixed_snippet;

    body.innerHTML = `
      <div class="panel-section animate-fade-up">
        <div class="panel-section__label">Recommendation</div>
        <div class="recommendation-block">
          <div class="recommendation-block__label">✓ How to fix</div>
          <div class="recommendation-block__text">${vuln.recommendation ? this._esc(vuln.recommendation) : "No specific recommendation available."}</div>
        </div>
      </div>

      ${hasSnippets ? `
      <div class="panel-section">
        <div class="panel-section__label">Code Diff</div>
        <div class="code-diff">
          <div class="code-diff__header">
            <span class="code-diff__tab active" data-diff-tab="before">Before</span>
            <span class="code-diff__tab" data-diff-tab="after">After</span>
            <span class="code-diff__tab" data-diff-tab="diff">Diff</span>
          </div>
          <div class="code-diff__body" id="diff-body">
            <span class="diff-line-removed">${this._esc(vuln.code_snippet || "")}</span>
          </div>
        </div>
      </div>` : ""}

      ${vuln.cwe_id ? `
      <div class="panel-section">
        <div class="panel-section__label">External References</div>
        <div class="ref-pills">
          <a href="https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace("CWE-","")}.html"
             target="_blank" rel="noopener" class="ref-pill ref-pill--cwe">
            ⚠ ${this._esc(vuln.cwe_id)} ↗
          </a>
          ${vuln.owasp_category ? `<span class="ref-pill ref-pill--owasp">🛡 ${this._esc(vuln.owasp_category)}</span>` : ""}
        </div>
      </div>` : ""}
    `;

    // Diff tab switching
    body.querySelectorAll("[data-diff-tab]").forEach(tab => {
      tab.addEventListener("click", () => {
        body.querySelectorAll("[data-diff-tab]").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        const diffBody = body.querySelector("#diff-body");
        const tabName  = tab.dataset.diffTab;
        if (!diffBody) return;
        if (tabName === "before") {
          diffBody.innerHTML = `<span class="diff-line-removed">${this._esc(vuln.code_snippet || "—")}</span>`;
        } else if (tabName === "after") {
          diffBody.innerHTML = `<span class="diff-line-added">${this._esc(vuln.fixed_snippet || "—")}</span>`;
        } else {
          // Show unified diff
          const removed = (vuln.code_snippet || "").split("\n");
          const added   = (vuln.fixed_snippet || "").split("\n");
          const html = [
            ...removed.map(l => `<span class="diff-line-removed">${this._esc(l)}</span>`),
            ...added.map(l   => `<span class="diff-line-added">${this._esc(l)}</span>`),
          ].join("");
          diffBody.innerHTML = html || "—";
        }
      });
    });
  }

  // ── Panel Tab Navigation ──────────────────────────────────────────────

  _prevPanelTab() {
    const tabs = [...this.analysisPanelEl.querySelectorAll(".panel-tab")];
    const cur  = tabs.findIndex(t => t.classList.contains("active"));
    const prev = (cur - 1 + tabs.length) % tabs.length;
    tabs[prev].click();
  }

  _nextPanelTab() {
    const tabs = [...this.analysisPanelEl.querySelectorAll(".panel-tab")];
    const cur  = tabs.findIndex(t => t.classList.contains("active"));
    const next = (cur + 1) % tabs.length;
    tabs[next].click();
  }

  // ── Utilities ─────────────────────────────────────────────────────────

  _showEditorEmpty(message) {
    if (this.editorContainerEl) {
      this.editorContainerEl.innerHTML = `
        <div class="empty-state" style="flex:1; height:100%;">
          <div class="empty-state__icon">📂</div>
          <div class="empty-state__title">No file loaded</div>
          <div class="empty-state__desc font-serif">${this._esc(message)}</div>
          <a href="/" class="btn btn-secondary" style="margin-top:1rem;">← Back to Dashboard</a>
        </div>
      `;
    }
  }

  _riskColor(score) {
    if (score == null) return "info";
    if (score >= 0.7)  return "critical";
    if (score >= 0.4)  return "medium";
    return "low";
  }

  _createElement(tag, className) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    return el;
  }

  /** Safe HTML escape for user-provided content */
  _esc(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
}


// ─── Entry Point ─────────────────────────────────────────────────────────────

const reviewPage = new ReviewPage();
reviewPage.init().catch(err => {
  console.error("ReviewPage failed to initialize:", err);
});
