/**
 * shap_chart.js — SHAP / LIME Explanation Chart Renderer
 * ========================================================
 * Renders interactive feature importance visualizations onto HTML Canvas elements.
 * Supports both SHAP (diverging bar chart from base_value) and
 * LIME (simple horizontal bar chart with weights).
 *
 * Design decisions:
 *   - Pure Canvas API — no dependencies, no SVG library
 *   - Responsive: re-renders on container resize via ResizeObserver
 *   - Animated: bars grow from zero on first render
 *   - Interactive: hover highlights individual features with tooltip
 *
 * Usage:
 *   import { SHAPChart, LIMEChart } from './shap_chart.js';
 *
 *   const chart = new SHAPChart(canvasElement, explanationData);
 *   chart.render();
 *
 *   // Update with new data (re-animates):
 *   chart.update(newExplanationData);
 *
 *   // Clean up:
 *   chart.destroy();
 */


// ─── Design tokens (must match CSS variables) ────────────────────────────────

const COLORS = {
  bgRaised:      "#161b27",
  bgOverlay:     "#1e2535",
  borderDefault: "#2a3347",
  textPrimary:   "#e8eaf0",
  textSecondary: "#8892a4",
  textMuted:     "#4a5568",
  amberBright:   "#f59e0b",
  sevCritical:   "#ef4444",
  sevHigh:       "#f97316",
  sevLow:        "#22c55e",
  sevInfo:       "#38bdf8",
  fontMono:      "'JetBrains Mono', 'DM Mono', monospace",
  fontSerif:     "'Lora', Georgia, serif",
};

// Animation duration in ms
const ANIM_DURATION = 600;

// easeOutCubic easing function
const ease = t => 1 - Math.pow(1 - t, 3);


// ─── Base Chart Class ─────────────────────────────────────────────────────────

class BaseChart {
  /**
   * @param {HTMLCanvasElement} canvas  The canvas to render into
   * @param {object}            data    Explanation data object
   */
  constructor(canvas, data) {
    this.canvas  = canvas;
    this.ctx     = canvas.getContext("2d");
    this.data    = data;
    this._animId = null;
    this._startT = null;
    this._hoverIndex = -1;

    // Make canvas responsive
    this._ro = new ResizeObserver(() => this._onResize());
    this._ro.observe(canvas.parentElement || canvas);

    // Mouse interaction
    this._onMouseMove = this._handleMouseMove.bind(this);
    this._onMouseLeave = this._handleMouseLeave.bind(this);
    canvas.addEventListener("mousemove", this._onMouseMove);
    canvas.addEventListener("mouseleave", this._onMouseLeave);
  }

  _onResize() {
    this._setSize();
    this.render(false); // re-render without animation on resize
  }

  _setSize() {
    const parent = this.canvas.parentElement || document.body;
    const dpr    = window.devicePixelRatio || 1;
    const w      = parent.clientWidth  || 320;
    const h      = this._computeHeight(w);

    this.canvas.width  = w * dpr;
    this.canvas.height = h * dpr;
    this.canvas.style.width  = `${w}px`;
    this.canvas.style.height = `${h}px`;
    this.ctx.scale(dpr, dpr);

    this._w = w;
    this._h = h;
  }

  /** Override in subclass to return chart height based on data */
  _computeHeight(width) { return 200; }

  /** Override in subclass with actual drawing logic */
  _draw(progress) {}

  /** Override to map canvas Y position to feature index */
  _hitTest(y) { return -1; }

  _handleMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    const y    = e.clientY - rect.top;
    const idx  = this._hitTest(y);
    if (idx !== this._hoverIndex) {
      this._hoverIndex = idx;
      this._draw(1); // re-draw at full progress
    }
  }

  _handleMouseLeave() {
    this._hoverIndex = -1;
    this._draw(1);
  }

  /**
   * Render the chart. If `animate` is true (default), plays the grow-in animation.
   * @param {boolean} [animate=true]
   */
  render(animate = true) {
    this._setSize();
    if (!animate) {
      this._draw(1);
      return;
    }

    // Animate
    if (this._animId) cancelAnimationFrame(this._animId);
    this._startT = null;

    const step = (timestamp) => {
      if (!this._startT) this._startT = timestamp;
      const elapsed  = timestamp - this._startT;
      const progress = Math.min(elapsed / ANIM_DURATION, 1);
      this._draw(ease(progress));
      if (progress < 1) {
        this._animId = requestAnimationFrame(step);
      }
    };
    this._animId = requestAnimationFrame(step);
  }

  /**
   * Update with new data and re-render with animation.
   * @param {object} newData
   */
  update(newData) {
    this.data = newData;
    this.render(true);
  }

  /** Clean up event listeners and observers. */
  destroy() {
    if (this._animId) cancelAnimationFrame(this._animId);
    this._ro.disconnect();
    this.canvas.removeEventListener("mousemove", this._onMouseMove);
    this.canvas.removeEventListener("mouseleave", this._onMouseLeave);
  }

  // ── Drawing helpers ────────────────────────────────────────────────────

  _clearCanvas() {
    this.ctx.clearRect(0, 0, this._w, this._h);
  }

  _drawText(text, x, y, { size = 12, color = COLORS.textSecondary, font = COLORS.fontMono, align = "left", baseline = "middle", maxWidth } = {}) {
    const ctx = this.ctx;
    ctx.save();
    ctx.font        = `${size}px ${font}`;
    ctx.fillStyle   = color;
    ctx.textAlign   = align;
    ctx.textBaseline = baseline;
    if (maxWidth) {
      ctx.fillText(text, x, y, maxWidth);
    } else {
      ctx.fillText(text, x, y);
    }
    ctx.restore();
  }

  _drawRoundRect(x, y, w, h, r, fillStyle) {
    const ctx = this.ctx;
    if (w === 0) return;
    ctx.save();
    ctx.fillStyle = fillStyle;
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, w, h, r);
    } else {
      // Polyfill for older browsers
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + w - r, y);
      ctx.quadraticCurveTo(x + w, y, x + w, y + r);
      ctx.lineTo(x + w, y + h - r);
      ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
      ctx.lineTo(x + r, y + h);
      ctx.quadraticCurveTo(x, y + h, x, y + h - r);
      ctx.lineTo(x, y + r);
      ctx.quadraticCurveTo(x, y, x + r, y);
      ctx.closePath();
    }
    ctx.fill();
    ctx.restore();
  }
}


// ─── SHAP Chart ───────────────────────────────────────────────────────────────

/**
 * Renders a SHAP waterfall/diverging bar chart.
 *
 * Layout:
 *   [ feature label ] [ ←neg bar | center | pos bar→ ] [ ±value ]
 *
 * Each bar extends left (negative SHAP, reduces risk → green)
 * or right (positive SHAP, increases risk → red/amber) from the center axis.
 */
export class SHAPChart extends BaseChart {

  constructor(canvas, data) {
    super(canvas, data);

    // Layout constants (computed relative to canvas width in _draw)
    this.ROW_H    = 36;    // Height of each feature row
    this.PAD_TOP  = 40;    // Space for title + axis label
    this.PAD_BOT  = 32;    // Space for legend
    this.PAD_L    = 8;
    this.PAD_R    = 8;
    this.LABEL_W  = 148;   // Width of feature name column
    this.VAL_W    = 48;    // Width of value column
    this.GAP      = 6;     // Gap between label and bar
  }

  get features() {
    return (this.data?.features || [])
      .slice()
      .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
      .slice(0, 8); // Show top 8 features max
  }

  _computeHeight() {
    const n = Math.max(this.features.length, 1);
    return this.PAD_TOP + n * this.ROW_H + this.PAD_BOT + 20;
  }

  _hitTest(y) {
    const topOffset = this.PAD_TOP;
    const idx = Math.floor((y - topOffset) / this.ROW_H);
    if (idx >= 0 && idx < this.features.length) return idx;
    return -1;
  }

  _draw(progress) {
    this._clearCanvas();
    const ctx = this.ctx;
    const { _w: W, _h: H } = this;
    const features = this.features;

    // Background
    ctx.fillStyle = COLORS.bgRaised;
    ctx.fillRect(0, 0, W, H);

    if (features.length === 0) {
      this._drawText("No explanation data available", W / 2, H / 2, {
        color: COLORS.textMuted, align: "center", size: 12,
      });
      return;
    }

    // Compute max absolute SHAP value for scaling
    const maxAbs = Math.max(...features.map(f => Math.abs(f.shap_value)), 0.01);

    // Bar area: between LABEL_W+GAP and W-VAL_W-PAD_R
    const barAreaX = this.PAD_L + this.LABEL_W + this.GAP;
    const barAreaW = W - barAreaX - this.VAL_W - this.PAD_R;
    const centerX  = barAreaX + barAreaW / 2;

    // ── Title ──
    this._drawText("Feature Contributions (SHAP)", this.PAD_L, 14, {
      size: 10, color: COLORS.textMuted, font: COLORS.fontMono,
    });

    // Axis labels
    this._drawText("↓ reduces risk", barAreaX + 4, 28, { size: 9, color: COLORS.sevLow });
    this._drawText("↑ increases risk", W - this.VAL_W - this.PAD_R - 4, 28, {
      size: 9, color: COLORS.sevCritical, align: "right",
    });

    // ── Feature rows ──
    features.forEach((feat, i) => {
      const rowY  = this.PAD_TOP + i * this.ROW_H;
      const midY  = rowY + this.ROW_H / 2;
      const isHov = i === this._hoverIndex;

      // Row hover background
      if (isHov) {
        ctx.fillStyle = COLORS.bgOverlay;
        ctx.fillRect(0, rowY, W, this.ROW_H);
      }

      // Feature label
      const labelColor = isHov ? COLORS.textPrimary : COLORS.textSecondary;
      const labelText  = feat.display || feat.name;
      this._drawText(labelText, this.PAD_L, midY, {
        size: 10.5, color: labelColor, font: COLORS.fontMono,
        maxWidth: this.LABEL_W - 4,
      });

      // Center axis line
      ctx.strokeStyle = COLORS.borderDefault;
      ctx.lineWidth   = 1;
      ctx.beginPath();
      ctx.moveTo(centerX, rowY + 4);
      ctx.lineTo(centerX, rowY + this.ROW_H - 4);
      ctx.stroke();

      // Bar
      const shap    = feat.shap_value;
      const barMaxW = (barAreaW / 2) - 4;
      const barW    = (Math.abs(shap) / maxAbs) * barMaxW * progress;
      const barH    = 10;
      const barY    = midY - barH / 2;

      if (shap > 0) {
        // Positive → extends right from center (red/orange = increases risk)
        const grad = ctx.createLinearGradient(centerX, 0, centerX + barW, 0);
        grad.addColorStop(0, COLORS.sevHigh);
        grad.addColorStop(1, COLORS.sevCritical);
        this._drawRoundRect(centerX + 1, barY, barW, barH, 3, isHov ? COLORS.sevCritical : grad);
      } else {
        // Negative → extends left from center (green = reduces risk)
        const grad = ctx.createLinearGradient(centerX - barW, 0, centerX, 0);
        grad.addColorStop(0, "#16a34a");
        grad.addColorStop(1, COLORS.sevLow);
        this._drawRoundRect(centerX - barW - 1, barY, barW, barH, 3, isHov ? COLORS.sevLow : grad);
      }

      // Value label
      const valueStr = (shap > 0 ? "+" : "") + shap.toFixed(3);
      const valColor = shap > 0 ? COLORS.sevHigh : COLORS.sevLow;
      this._drawText(valueStr, W - this.PAD_R, midY, {
        size: 10, color: isHov ? COLORS.textPrimary : valColor,
        align: "right", font: COLORS.fontMono,
      });

      // Hover tooltip
      if (isHov) {
        const tooltipText = `${feat.display || feat.name}: ${valueStr}`;
        const tw = Math.min(tooltipText.length * 6.5 + 16, 280);
        const tx = Math.min(centerX + 10, W - tw - 4);
        const ty = rowY - 2;

        ctx.fillStyle = COLORS.bgOverlay;
        ctx.strokeStyle = COLORS.borderDefault;
        ctx.lineWidth = 1;
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(tx, ty, tw, 22, 4);
        ctx.fill();
        ctx.stroke();

        this._drawText(tooltipText, tx + 8, ty + 11, {
          size: 10, color: COLORS.textPrimary, font: COLORS.fontMono,
        });
      }
    });

    // ── Center axis full line ──
    ctx.strokeStyle = COLORS.borderDefault;
    ctx.lineWidth   = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(centerX, this.PAD_TOP);
    ctx.lineTo(centerX, H - this.PAD_BOT);
    ctx.stroke();
    ctx.setLineDash([]);

    // ── Legend ──
    const legY = H - this.PAD_BOT + 10;
    this._drawRoundRect(barAreaX, legY, 12, 8, 2, COLORS.sevCritical);
    this._drawText("Increases risk", barAreaX + 16, legY + 4, { size: 9.5, color: COLORS.textMuted });
    this._drawRoundRect(barAreaX + 110, legY, 12, 8, 2, COLORS.sevLow);
    this._drawText("Reduces risk",   barAreaX + 126, legY + 4, { size: 9.5, color: COLORS.textMuted });

    // ── Prediction score ──
    const pred    = this.data?.prediction;
    const predStr = pred !== undefined ? `Prediction: ${(pred * 100).toFixed(0)}%` : "";
    if (predStr) {
      this._drawText(predStr, W - this.PAD_R, legY + 4, {
        size: 9.5, color: COLORS.amberBright, align: "right",
      });
    }
  }
}


// ─── LIME Chart ───────────────────────────────────────────────────────────────

/**
 * Renders a LIME local explanation as a simple horizontal bar chart.
 * Bars are colored by weight direction (positive = red, negative = green).
 */
export class LIMEChart extends BaseChart {

  constructor(canvas, data) {
    super(canvas, data);
    this.ROW_H   = 32;
    this.PAD_TOP = 36;
    this.PAD_BOT = 48;
    this.PAD_L   = 8;
    this.PAD_R   = 8;
    this.LABEL_W = 140;
    this.VAL_W   = 52;
    this.GAP     = 6;
  }

  get features() {
    return (this.data?.features || [])
      .slice()
      .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
      .slice(0, 7);
  }

  _computeHeight() {
    return this.PAD_TOP + this.features.length * this.ROW_H + this.PAD_BOT + 16;
  }

  _hitTest(y) {
    const idx = Math.floor((y - this.PAD_TOP) / this.ROW_H);
    if (idx >= 0 && idx < this.features.length) return idx;
    return -1;
  }

  _draw(progress) {
    this._clearCanvas();
    const { ctx, _w: W, _h: H } = this;
    const features = this.features;

    ctx.fillStyle = COLORS.bgRaised;
    ctx.fillRect(0, 0, W, H);

    if (features.length === 0) {
      this._drawText("No LIME data available", W / 2, H / 2, {
        color: COLORS.textMuted, align: "center", size: 12,
      });
      return;
    }

    const maxAbs   = Math.max(...features.map(f => Math.abs(f.weight)), 0.01);
    const barAreaX = this.PAD_L + this.LABEL_W + this.GAP;
    const barAreaW = W - barAreaX - this.VAL_W - this.PAD_R;

    // Title
    this._drawText("Feature Weights (LIME)", this.PAD_L, 14, { size: 10, color: COLORS.textMuted });

    // Probability bar
    const proba   = this.data?.prediction_proba?.[1] ?? 0;
    const probaW  = Math.round(barAreaW * proba);
    const probaY  = 26;
    const probaH  = 6;

    this._drawText("Predicted:", this.PAD_L, probaY + 3, { size: 9, color: COLORS.textMuted });
    ctx.fillStyle = COLORS.borderDefault;
    ctx.beginPath(); ctx.roundRect?.(barAreaX, probaY, barAreaW, probaH, 3); ctx.fill();

    const pGrad = ctx.createLinearGradient(barAreaX, 0, barAreaX + probaW * progress, 0);
    pGrad.addColorStop(0, COLORS.amberBright);
    pGrad.addColorStop(1, COLORS.sevCritical);
    this._drawRoundRect(barAreaX, probaY, probaW * progress, probaH, 3, pGrad);
    this._drawText(`${(proba * 100).toFixed(0)}%`, W - this.PAD_R, probaY + 3, {
      size: 9.5, color: COLORS.amberBright, align: "right",
    });

    // Feature rows
    features.forEach((feat, i) => {
      const rowY  = this.PAD_TOP + i * this.ROW_H;
      const midY  = rowY + this.ROW_H / 2;
      const isHov = i === this._hoverIndex;

      if (isHov) {
        ctx.fillStyle = COLORS.bgOverlay;
        ctx.fillRect(0, rowY, W, this.ROW_H);
      }

      // Label
      this._drawText(feat.display || feat.name, this.PAD_L, midY, {
        size: 10, color: isHov ? COLORS.textPrimary : COLORS.textSecondary,
        maxWidth: this.LABEL_W - 4,
      });

      // Bar (starts from left edge of bar area)
      const barMaxW = barAreaW - 4;
      const barW    = (Math.abs(feat.weight) / maxAbs) * barMaxW * progress;
      const barH    = 8;
      const barY    = midY - barH / 2;

      const fillColor = feat.weight > 0
        ? (isHov ? COLORS.sevCritical : COLORS.sevHigh)
        : (isHov ? COLORS.sevLow : "#16a34a");

      this._drawRoundRect(barAreaX, barY, barW, barH, 3, fillColor);

      // Background track
      ctx.fillStyle = COLORS.bgOverlay;
      ctx.globalCompositeOperation = "destination-over";
      ctx.beginPath(); ctx.roundRect?.(barAreaX, barY, barAreaW, barH, 3); ctx.fill();
      ctx.globalCompositeOperation = "source-over";

      // Value
      const valStr   = (feat.weight > 0 ? "+" : "") + feat.weight.toFixed(3);
      const valColor = feat.weight > 0 ? COLORS.sevHigh : COLORS.sevLow;
      this._drawText(valStr, W - this.PAD_R, midY, {
        size: 10, color: isHov ? COLORS.textPrimary : valColor, align: "right",
      });
    });

    // Legend
    const legY = H - this.PAD_BOT + 14;
    this._drawRoundRect(barAreaX, legY, 10, 8, 2, COLORS.sevHigh);
    this._drawText("Positive weight (increases risk)", barAreaX + 14, legY + 4, { size: 9, color: COLORS.textMuted });
    this._drawRoundRect(barAreaX, legY + 16, 10, 8, 2, COLORS.sevLow);
    this._drawText("Negative weight (reduces risk)",  barAreaX + 14, legY + 20, { size: 9, color: COLORS.textMuted });
  }
}


// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Creates the appropriate chart type based on explanation method.
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object}            data    Full explanation_data object
 * @returns {SHAPChart|LIMEChart}
 */
export function createExplanationChart(canvas, data) {
  if (data?.method === "lime") {
    return new LIMEChart(canvas, data);
  }
  return new SHAPChart(canvas, data);
}
