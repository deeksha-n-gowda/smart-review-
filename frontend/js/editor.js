/**
 * editor.js — Code Editor Renderer
 * ==================================
 * Renders source code with:
 *   - Line numbers + gutter vulnerability markers
 *   - Per-language syntax highlighting (tokenizer, no external libs)
 *   - Clickable vulnerability annotations that expand inline
 *   - Smooth scroll-to-line on vulnerability selection
 *   - Keyboard navigation (ArrowUp/Down to cycle vulnerabilities)
 *
 * The editor renders source code as a DOM table — not a <canvas> —
 * so it remains fully accessible (selectable text, Ctrl+F searchable).
 *
 * Usage:
 *   import { CodeEditor } from './editor.js';
 *
 *   const editor = new CodeEditor(containerElement);
 *   editor.loadFile(fileData, sourceCode);
 *   editor.onVulnerabilitySelect = (vuln) => { ... };
 */

// ─── Tokenizers ───────────────────────────────────────────────────────────────

/**
 * Simple regex-based tokenizers for each supported language.
 * Returns an array of { type, value } tokens for a single line of code.
 * Not a full parser — covers the common cases visually well enough.
 *
 * Token types map to .tok-* CSS classes in editor.css.
 */
const Tokenizers = {

  python(line) {
    const rules = [
      { type: "comment",   re: /(#.*)/ },
      { type: "string",    re: /("""[\s\S]*?"""|'''[\s\S]*?''')/ },
      { type: "string",    re: /(f"(?:[^"\\]|\\.)*"|f'(?:[^'\\]|\\.)*')/ },
      { type: "string",    re: /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/ },
      { type: "decorator", re: /(@\w+)/ },
      { type: "keyword",   re: /\b(and|as|assert|async|await|break|class|continue|def|del|elif|else|except|False|finally|for|from|global|if|import|in|is|lambda|None|nonlocal|not|or|pass|raise|return|True|try|while|with|yield)\b/ },
      { type: "builtin",   re: /\b(print|len|range|type|int|str|float|list|dict|set|tuple|bool|open|input|zip|map|filter|enumerate|sorted|reversed|sum|min|max|abs|round|hasattr|getattr|setattr|isinstance|issubclass|super|property|staticmethod|classmethod)\b/ },
      { type: "number",    re: /\b(\d+\.?\d*(?:[eE][+-]?\d+)?|0x[0-9a-fA-F]+)\b/ },
      { type: "funcname",  re: /\bdef\s+(\w+)/ },
      { type: "classname", re: /\bclass\s+(\w+)/ },
    ];
    return _tokenize(line, rules);
  },

  javascript(line) {
    const rules = [
      { type: "comment",   re: /(\/\/.*)/ },
      { type: "string",    re: /(`(?:[^`\\]|\\.)*`)/ },
      { type: "string",    re: /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/ },
      { type: "regex",     re: /(\/(?:[^/\n\\]|\\.)+\/[gimsuy]*)/ },
      { type: "keyword",   re: /\b(async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|false|finally|for|from|function|if|import|in|instanceof|let|new|null|of|return|static|super|switch|this|throw|true|try|typeof|undefined|var|void|while|with|yield)\b/ },
      { type: "builtin",   re: /\b(console|document|window|Array|Object|String|Number|Boolean|Promise|fetch|JSON|Math|Date|Error|Map|Set|Symbol|Proxy|Reflect|setTimeout|setInterval|clearTimeout|clearInterval)\b/ },
      { type: "number",    re: /\b(\d+\.?\d*(?:[eE][+-]?\d+)?|0x[0-9a-fA-F]+)\b/ },
      { type: "decorator", re: /(@\w+)/ },
    ];
    return _tokenize(line, rules);
  },

  java(line) {
    const rules = [
      { type: "comment",   re: /(\/\/.*)/ },
      { type: "string",    re: /("(?:[^"\\]|\\.)*")/ },
      { type: "keyword",   re: /\b(abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|goto|if|implements|import|instanceof|int|interface|long|native|new|null|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|true|false|try|void|volatile|while|var|record|sealed|permits)\b/ },
      { type: "type",      re: /\b(String|Integer|Long|Double|Float|Boolean|Byte|Character|Short|Object|List|Map|Set|Collection|ArrayList|HashMap|Optional|Stream|StringBuilder)\b/ },
      { type: "number",    re: /\b(\d+\.?\d*[dDfFlL]?|0x[0-9a-fA-F]+)\b/ },
      { type: "decorator", re: /(@\w+)/ },
    ];
    return _tokenize(line, rules);
  },

  csharp(line) {
    const rules = [
      { type: "comment",   re: /(\/\/.*)/ },
      { type: "string",    re: /(@"(?:[^"]|"")*"|"(?:[^"\\]|\\.)*")/ },
      { type: "keyword",   re: /\b(abstract|as|base|bool|break|byte|case|catch|char|checked|class|const|continue|decimal|default|delegate|do|double|else|enum|event|explicit|extern|false|finally|fixed|float|for|foreach|goto|if|implicit|in|int|interface|internal|is|lock|long|namespace|new|null|object|operator|out|override|params|private|protected|public|readonly|ref|return|sbyte|sealed|short|sizeof|stackalloc|static|string|struct|switch|this|throw|true|try|typeof|uint|ulong|unchecked|unsafe|ushort|using|virtual|void|volatile|while|async|await|var|dynamic|yield|record|init|with|global)\b/ },
      { type: "type",      re: /\b(String|Int32|Int64|Double|Boolean|DateTime|List|Dictionary|IEnumerable|Task|CancellationToken|Exception|Console|Math)\b/ },
      { type: "number",    re: /\b(\d+\.?\d*[mMfFdDlLuU]?|0x[0-9a-fA-F]+)\b/ },
      { type: "decorator", re: /(\[[\w\s,="'()]+\])/ },
    ];
    return _tokenize(line, rules);
  },
};

/**
 * Generic tokenizer engine — splits `line` into tokens using `rules`.
 * Unmatched text becomes a "default" token.
 *
 * @param {string}              line
 * @param {{ type, re }[]}      rules
 * @returns {{ type: string, value: string }[]}
 */
function _tokenize(line, rules) {
  const tokens  = [];
  let remaining = line;

  while (remaining.length > 0) {
    let earliest = null;
    let earliestIndex = Infinity;
    let matchedRule   = null;

    for (const rule of rules) {
      const g = new RegExp(rule.re.source);
      const m = g.exec(remaining);
      if (m && m.index < earliestIndex) {
        earliest      = m;
        earliestIndex = m.index;
        matchedRule   = rule;
      }
    }

    if (!earliest || earliestIndex === Infinity) {
      // No more matches — rest is plain text
      tokens.push({ type: "default", value: remaining });
      break;
    }

    // Text before the match is plain
    if (earliestIndex > 0) {
      tokens.push({ type: "default", value: remaining.slice(0, earliestIndex) });
    }

    // The matched token (use capture group 1 if present)
    tokens.push({ type: matchedRule.type, value: earliest[1] || earliest[0] });
    remaining = remaining.slice(earliestIndex + (earliest[1] || earliest[0]).length);
  }

  return tokens;
}

/**
 * Converts a tokenised line to an HTML string with <span class="tok-*"> tags.
 * The `value` is HTML-escaped to prevent XSS from source code content.
 *
 * @param {{ type, value }[]} tokens
 * @returns {string} HTML string (safe — all values escaped)
 */
function tokensToHTML(tokens) {
  return tokens.map(tok => {
    const escaped = escapeHTML(tok.value);
    if (tok.type === "default") return escaped;
    return `<span class="tok-${tok.type}">${escaped}</span>`;
  }).join("");
}

/** HTML-escapes a string for safe insertion into innerHTML. */
function escapeHTML(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


// ─── CodeEditor Class ─────────────────────────────────────────────────────────

export class CodeEditor {

  /**
   * @param {HTMLElement} container  The element that will contain the editor
   */
  constructor(container) {
    this.container   = container;
    this.fileData    = null;    // { id, filename, language, vulnerabilities, ... }
    this.sourceLines = [];      // String[] — one per line
    this.selectedVulnId = null;

    /** Callback: called with the Vulnerability object when user clicks one. */
    this.onVulnerabilitySelect = null;

    this._buildShell();
    this._bindKeyboard();
  }

  // ── Setup ────────────────────────────────────────────────────────────────

  _buildShell() {
    // Toolbar (filename, metadata)
    this.toolbar = document.createElement("div");
    this.toolbar.className = "editor-toolbar";
    this.toolbar.innerHTML = `
      <div class="editor-toolbar__filename">
        <span class="dot"></span>
        <span class="filename-text">No file loaded</span>
      </div>
      <div class="editor-toolbar__meta">
        <span class="meta-lines">—</span>
        <span class="meta-lang">—</span>
        <span class="meta-risk"></span>
      </div>
    `;

    // Scrollable code area
    this.scroll = document.createElement("div");
    this.scroll.className = "editor-scroll";

    // The table that holds line number + code rows
    this.table = document.createElement("div");
    this.table.className = "editor-table";
    this.table.setAttribute("role", "code");
    this.table.setAttribute("aria-label", "Source code viewer");
    this.scroll.appendChild(this.table);

    this.container.appendChild(this.toolbar);
    this.container.appendChild(this.scroll);
  }

  _bindKeyboard() {
    document.addEventListener("keydown", (e) => {
      if (!this.fileData) return;
      const vulns = this._sortedVulns();
      if (vulns.length === 0) return;

      const currentIdx = vulns.findIndex(v => v.id === this.selectedVulnId);

      if (e.key === "ArrowDown" && e.altKey) {
        e.preventDefault();
        const next = currentIdx < vulns.length - 1 ? currentIdx + 1 : 0;
        this.selectVulnerability(vulns[next]);
      } else if (e.key === "ArrowUp" && e.altKey) {
        e.preventDefault();
        const prev = currentIdx > 0 ? currentIdx - 1 : vulns.length - 1;
        this.selectVulnerability(vulns[prev]);
      }
    });
  }

  _sortedVulns() {
    if (!this.fileData?.vulnerabilities) return [];
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...this.fileData.vulnerabilities]
      .sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Loads a file into the editor and renders it.
   *
   * @param {object} fileData    CodeFile object (with .vulnerabilities array)
   * @param {string} sourceCode  Decrypted plaintext source code
   */
  loadFile(fileData, sourceCode) {
    this.fileData    = fileData;
    this.sourceLines = sourceCode.split("\n");
    this.selectedVulnId = null;

    this._updateToolbar();
    this._render();
  }

  /**
   * Highlights and scrolls to a specific vulnerability.
   * Called from the vuln list panel when user clicks a vuln.
   *
   * @param {object} vuln  Vulnerability object
   */
  selectVulnerability(vuln) {
    if (!vuln) return;

    // Deselect previous
    const prev = this.table.querySelector(".editor-row.selected-" + (this._getSelectedSeverity()));
    if (prev) {
      prev.classList.remove(`selected-${this._getSelectedSeverity()}`);
      this._removeAnnotation();
    }

    this.selectedVulnId = vuln.id;

    // Add selection class to all lines in range
    const start = vuln.line_start;
    const end   = vuln.line_end || start;
    for (let ln = start; ln <= end; ln++) {
      const row = this.table.querySelector(`[data-line="${ln}"]`);
      if (row) row.classList.add(`selected-${vuln.severity}`);
    }

    // Insert inline annotation below the last line of the vuln
    this._insertAnnotation(vuln, end);

    // Scroll line into view (center it vertically)
    const targetRow = this.table.querySelector(`[data-line="${start}"]`);
    if (targetRow) {
      targetRow.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    // Fire callback
    if (this.onVulnerabilitySelect) {
      this.onVulnerabilitySelect(vuln);
    }
  }

  /**
   * Clears all highlights. Useful when switching files.
   */
  clearSelection() {
    this.selectedVulnId = null;
    this._removeAnnotation();
    this.table.querySelectorAll(".editor-row[class*='selected-']").forEach(row => {
      row.className = row.className.replace(/selected-\w+/g, "").trim();
    });
  }

  // ── Rendering ────────────────────────────────────────────────────────────

  _updateToolbar() {
    const f = this.fileData;
    if (!f) return;
    this.toolbar.querySelector(".filename-text").textContent = f.filename || "untitled";
    this.toolbar.querySelector(".meta-lines").textContent    = `${this.sourceLines.length} lines`;
    this.toolbar.querySelector(".meta-lang").innerHTML       = `<span class="lang-tag ${f.language}">${f.language}</span>`;
    const risk = f.risk_score != null ? `<span class="text-amber">Risk: ${Math.round(f.risk_score * 100)}%</span>` : "";
    this.toolbar.querySelector(".meta-risk").innerHTML = risk;
  }

  _render() {
    this.table.innerHTML = "";

    const lang     = this.fileData?.language || "python";
    const tokenize = Tokenizers[lang] || (line => [{ type: "default", value: line }]);

    // Build a map of line → vulnerabilities for quick lookup
    const vulnByLine = this._buildVulnLineMap();

    this.sourceLines.forEach((rawLine, i) => {
      const lineNum = i + 1;
      const vulns   = vulnByLine.get(lineNum) || [];
      const row     = this._createRow(lineNum, rawLine, vulns, tokenize);
      this.table.appendChild(row);
    });
  }

  /**
   * Builds a Map<lineNumber, Vulnerability[]> for efficient lookup.
   */
  _buildVulnLineMap() {
    const map = new Map();
    if (!this.fileData?.vulnerabilities) return map;

    this.fileData.vulnerabilities.forEach(vuln => {
      const start = vuln.line_start;
      const end   = vuln.line_end || start;
      for (let ln = start; ln <= end; ln++) {
        if (!map.has(ln)) map.set(ln, []);
        map.get(ln).push(vuln);
      }
    });

    return map;
  }

  /**
   * Creates a single row element for the code table.
   */
  _createRow(lineNum, rawLine, vulns, tokenize) {
    const row = document.createElement("div");
    row.className = "editor-row";
    row.dataset.line = lineNum;

    // Highlight class from the most severe vuln on this line
    if (vulns.length > 0) {
      const topSeverity = this._topSeverity(vulns);
      row.classList.add("has-vuln", `highlight-${topSeverity}`);
    }

    // Gutter (line number + optional marker)
    const gutter = document.createElement("div");
    gutter.className = "editor-gutter";

    const lineNumSpan = document.createElement("span");
    lineNumSpan.textContent = lineNum;
    gutter.appendChild(lineNumSpan);

    if (vulns.length > 0) {
      const topSeverity = this._topSeverity(vulns);
      const marker = document.createElement("span");
      marker.className = `gutter-marker gutter-marker-${topSeverity}`;
      marker.textContent = vulns.length > 1 ? vulns.length : "!";
      marker.title = vulns.map(v => v.title).join(", ");
      marker.addEventListener("click", (e) => {
        e.stopPropagation();
        this.selectVulnerability(vulns[0]);
      });
      gutter.appendChild(marker);
    }

    // Code content with syntax highlighting
    const content = document.createElement("div");
    content.className = "editor-line-content";

    // Tokenise and set HTML (escapeHTML is called inside tokensToHTML)
    const tokens  = tokenize(rawLine);
    const htmlStr = tokensToHTML(tokens);

    // Empty lines need a non-breaking space to preserve height
    content.innerHTML = htmlStr || "&nbsp;";

    // Click on line → select first vuln on that line
    if (vulns.length > 0) {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => {
        this.selectVulnerability(vulns[0]);
      });
    }

    row.appendChild(gutter);
    row.appendChild(content);
    return row;
  }

  // ── Inline Annotation ────────────────────────────────────────────────────

  _insertAnnotation(vuln, afterLine) {
    this._removeAnnotation(); // Remove any existing annotation

    const targetRow = this.table.querySelector(`[data-line="${afterLine}"]`);
    if (!targetRow) return;

    const annotationRow = document.createElement("div");
    annotationRow.className = "vuln-annotation";
    annotationRow.id = "active-annotation";

    const callout = document.createElement("div");
    callout.className = `vuln-callout vuln-callout--${vuln.severity}`;

    callout.innerHTML = `
      <div class="vuln-callout__title">
        <span class="vuln-dot vuln-dot-${vuln.severity}"></span>
        ${escapeHTML(vuln.title)}
        <span class="badge badge-${vuln.severity}" style="font-size:10px; padding:1px 6px;">${vuln.severity}</span>
      </div>
      <div class="vuln-callout__text">${escapeHTML(
        vuln.description.length > 160
          ? vuln.description.slice(0, 157) + "…"
          : vuln.description
      )}</div>
      <div class="vuln-callout__actions">
        <button class="btn btn-sm btn-ghost" data-action="show-fix" style="font-size:10px; padding:2px 8px;">
          View fix →
        </button>
        ${vuln.cwe_id ? `<span class="ref-pill ref-pill--cwe" style="font-size:10px;">${escapeHTML(vuln.cwe_id)}</span>` : ""}
      </div>
    `;

    // "View fix" fires the same callback so the right panel updates
    callout.querySelector("[data-action='show-fix']")?.addEventListener("click", () => {
      if (this.onVulnerabilitySelect) this.onVulnerabilitySelect(vuln);
    });

    annotationRow.appendChild(callout);
    targetRow.insertAdjacentElement("afterend", annotationRow);
  }

  _removeAnnotation() {
    const existing = this.table.querySelector("#active-annotation");
    if (existing) existing.remove();
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  _topSeverity(vulns) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return vulns.reduce((top, v) =>
      (order[v.severity] ?? 5) < (order[top] ?? 5) ? v.severity : top,
      vulns[0]?.severity
    );
  }

  _getSelectedSeverity() {
    if (!this.selectedVulnId || !this.fileData?.vulnerabilities) return "medium";
    const v = this.fileData.vulnerabilities.find(v => v.id === this.selectedVulnId);
    return v?.severity || "medium";
  }
}
