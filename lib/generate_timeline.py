#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
generate_timeline.py — Vertical swimlane timeline PNGs and interactive HTML.

Three timelines per investigation:
  * Attacker perspective  — timestamped events extracted from evidence
  * Defender perspective  — analyst investigation steps (RN-NNN)
  * Combined key events   — critical + high severity from both

Each timeline is paginated at PAGE_MAX_EVENTS per page (no overlapping text ever —
each event occupies a fixed row).
"""
from __future__ import annotations

import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Palette (matches the dark report theme)
# ---------------------------------------------------------------------------
_BG        = "#0A1628"
_HEADER_BG = "#0D1E35"
_DIVIDER   = "#1565C0"
_ROW_ALT   = "#0C1A30"
_LABEL     = "#FFFFFF"
_SUBLABEL  = "#B0BEC5"
_TITLE_COL = "#FFFFFF"

_MODULE_COLORS: dict[str, str] = {
    "FAN":  "#43A047",
    "FAME": "#2979FF",
    "FAST": "#FF9800",
    "RN":   "#607D8B",
}

_SEVERITY_SIZE: dict[str, int] = {
    "critical": 14,
    "high":     10,
    "medium":    7,
    "low":       5,
    "info":      4,
}

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#F44336",
    "high":     "#FF9800",
    "medium":   "#FFC107",
    "low":      "#4CAF50",
    "info":     "#90A4AE",
}

# Layout constants (pixels at DPI=150)
PAGE_MAX_EVENTS = 12
ROW_HEIGHT_PX   = 70
HEADER_PX       = 90
FOOTER_PX       = 55
WIDTH_PX        = 1600
DPI             = 150

# Column x-positions in axes-fraction coordinates (0-1)
TIME_COL = 0.17   # right edge of timestamp column
DOT_X    = 0.205  # centre of severity dot
SEV_X    = 0.225  # left edge of severity badge
DESC_X   = 0.310  # left edge of description text
MOD_X    = 0.985  # right edge of module tag


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts_str: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str.replace(" UTC", "").strip(), fmt.replace(" UTC", ""))
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _module_color(module: str) -> str:
    return _MODULE_COLORS.get((module or "").upper(), _MODULE_COLORS["RN"])


def _module_from_step_id(step_id: str) -> str:
    sid = (step_id or "").upper()
    for prefix in ("FAME", "FAST", "FAN"):
        if sid.startswith(prefix):
            return prefix
    return "RN"


def _step_to_event(s: dict) -> dict:
    """Convert a research_notes step dict to the internal event format."""
    outcome = s.get("outcome", "")
    title   = s.get("title", "")
    return {
        "timestamp":     s.get("timestamp", ""),
        "description":   f"{title} — {outcome[:100]}" if outcome else title,
        "severity":      "info",
        "module":        _module_from_step_id(s.get("id", "")),
        "source_detail": s.get("action", ""),
    }


# ---------------------------------------------------------------------------
# Core swimlane page renderer
# ---------------------------------------------------------------------------

def _render_swimlane_page(
    events: list[dict],
    page_num: int,
    total_pages: int,
    title: str,
    output_path: Path,
    time_range: tuple[str, str] | None = None,
) -> Path:
    """Render one page of events as a vertical swimlane PNG (no overlapping labels)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    n = max(len(events), 1)
    total_px = HEADER_PX + n * ROW_HEIGHT_PX + FOOTER_PX
    fig_w = WIDTH_PX / DPI
    fig_h = total_px / DPI

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    def _yc(row_idx: int, fraction: float = 0.5) -> float:
        row_top = 1.0 - (HEADER_PX + row_idx * ROW_HEIGHT_PX) / total_px
        row_bot = 1.0 - (HEADER_PX + (row_idx + 1) * ROW_HEIGHT_PX) / total_px
        return row_bot + (row_top - row_bot) * fraction

    def _yt(fraction: float = 0.5) -> float:
        return 1.0 - HEADER_PX / total_px * (1.0 - fraction)

    def _yf(fraction: float = 0.5) -> float:
        return FOOTER_PX / total_px * fraction

    # ---- Header bar --------------------------------------------------------
    ax.add_patch(mpatches.FancyBboxPatch(
        (0.0, 1.0 - HEADER_PX / total_px), 1.0, HEADER_PX / total_px,
        boxstyle="square,pad=0", linewidth=0, facecolor=_HEADER_BG,
        transform=ax.transAxes, clip_on=False,
    ))

    ax.text(0.015, _yt(0.72), title,
            ha="left", va="center", color=_TITLE_COL,
            fontsize=11, fontweight="bold", transform=ax.transAxes)

    if time_range:
        ax.text(0.5, _yt(0.72), f"{time_range[0]}  —  {time_range[1]}",
                ha="center", va="center", color=_SUBLABEL,
                fontsize=8, transform=ax.transAxes)

    if total_pages > 1:
        ax.text(0.985, _yt(0.72), f"Page {page_num} of {total_pages}",
                ha="right", va="center", color=_SUBLABEL,
                fontsize=8, transform=ax.transAxes)

    # Column headings
    for x, lbl, ha in [
        (TIME_COL - 0.008, "TIMESTAMP", "right"),
        (SEV_X,            "SEVERITY",  "left"),
        (DESC_X,           "EVENT",     "left"),
        (MOD_X,            "MODULE",    "right"),
    ]:
        ax.text(x, _yt(0.22), lbl, ha=ha, va="center",
                color=_SUBLABEL, fontsize=6.5, fontweight="bold",
                transform=ax.transAxes)

    # Thin separator under column headings
    ax.plot([0, 1], [1.0 - HEADER_PX / total_px, 1.0 - HEADER_PX / total_px],
            color=_DIVIDER, linewidth=1.0, transform=ax.transAxes, clip_on=False)

    # Vertical divider between timestamp column and content
    content_top = 1.0 - HEADER_PX / total_px
    content_bot = FOOTER_PX / total_px
    ax.plot([TIME_COL, TIME_COL], [content_bot, content_top],
            color=_DIVIDER, linewidth=0.8, alpha=0.6,
            transform=ax.transAxes, clip_on=False)

    # ---- Empty state -------------------------------------------------------
    if not events:
        ax.text(0.5, 0.5, "No events recorded.",
                ha="center", va="center", color=_SUBLABEL, fontsize=10,
                transform=ax.transAxes)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout(pad=0)
        fig.savefig(str(output_path), dpi=DPI, bbox_inches="tight",
                    facecolor=_BG, edgecolor="none")
        plt.close(fig)
        return output_path

    # ---- Event rows --------------------------------------------------------
    for i, ev in enumerate(events):
        y_ctr = _yc(i, 0.5)
        y_top = _yc(i, 1.0)
        y_bot = _yc(i, 0.0)

        if i % 2 == 1:
            ax.add_patch(mpatches.FancyBboxPatch(
                (0.0, y_bot), 1.0, y_top - y_bot,
                boxstyle="square,pad=0", linewidth=0, facecolor=_ROW_ALT,
                transform=ax.transAxes, clip_on=False,
            ))

        ax.plot([0, 1], [y_bot, y_bot],
                color=_DIVIDER, linewidth=0.4, alpha=0.35,
                transform=ax.transAxes, clip_on=False)

        # Timestamp
        ts = ev.get("timestamp", "")
        if ts:
            dt = _parse_ts(ts)
            ts_display = dt.strftime("%Y-%m-%d\n%H:%M UTC") if dt else ts
        else:
            ts_display = "—"
        ax.text(TIME_COL - 0.010, y_ctr, ts_display,
                ha="right", va="center", color=_SUBLABEL,
                fontsize=7, linespacing=1.3, transform=ax.transAxes)

        # Severity dot
        severity  = ev.get("severity", "info").lower()
        dot_size  = _SEVERITY_SIZE.get(severity, 5)
        dot_color = _module_color(ev.get("module", ""))
        ax.plot(DOT_X, y_ctr, "o", markersize=dot_size, color=dot_color,
                transform=ax.transAxes, zorder=5, clip_on=False)
        if severity == "critical":
            ax.plot(DOT_X, y_ctr, "o", markersize=dot_size + 6,
                    color=dot_color, alpha=0.30,
                    transform=ax.transAxes, zorder=4, clip_on=False)

        # Severity badge
        ax.text(SEV_X, y_ctr, f"[{severity.upper()}]",
                ha="left", va="center",
                color=_SEVERITY_COLOR.get(severity, "#90A4AE"),
                fontsize=6.5, fontweight="bold", transform=ax.transAxes)

        # Description (pre-wrapped, max 2 lines)
        raw_desc = ev.get("description", "")
        wrapped_lines = textwrap.fill(raw_desc, width=88).splitlines()
        if len(wrapped_lines) > 2:
            wrapped_lines = wrapped_lines[:2]
            wrapped_lines[-1] = wrapped_lines[-1][:85] + "…"
        ax.text(DESC_X, y_ctr, "\n".join(wrapped_lines),
                ha="left", va="center", color=_LABEL,
                fontsize=8, linespacing=1.3, transform=ax.transAxes)

        # Module tag
        module = ev.get("module", "")
        if module:
            ax.text(MOD_X, y_ctr, f"[{module}]",
                    ha="right", va="center",
                    color=_module_color(module),
                    fontsize=7, fontweight="bold", transform=ax.transAxes)

    # ---- Footer: legend ----------------------------------------------------
    seen_modules = sorted({ev.get("module", "") for ev in events if ev.get("module")})
    mod_patches  = [mpatches.Patch(color=_module_color(m), label=m) for m in seen_modules]
    sev_patches  = [
        mpatches.Patch(color=_SEVERITY_COLOR["critical"], label="Critical"),
        mpatches.Patch(color=_SEVERITY_COLOR["high"],     label="High"),
        mpatches.Patch(color=_SEVERITY_COLOR["medium"],   label="Medium"),
        mpatches.Patch(color=_SEVERITY_COLOR["low"],      label="Low"),
    ]

    y_leg = _yf(0.65)
    kw = dict(framealpha=0.0, fontsize=7, labelcolor=_LABEL,
              handlelength=1.0, handleheight=0.8, borderpad=0.2, columnspacing=0.7)
    if mod_patches:
        leg1 = ax.legend(handles=mod_patches, loc="lower left",
                         bbox_to_anchor=(0.01, y_leg), ncol=len(mod_patches), **kw)
        ax.add_artist(leg1)
    ax.legend(handles=sev_patches, loc="lower right",
              bbox_to_anchor=(0.99, y_leg), ncol=4, **kw)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout(pad=0)
    fig.savefig(str(output_path), dpi=DPI, bbox_inches="tight",
                facecolor=_BG, edgecolor="none")
    plt.close(fig)
    return output_path


def _render_unconfirmed_table(events: list[dict], output_path: Path, title: str) -> Path:
    """Render a plain table for findings with no confirmed timestamp."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    n = max(len(events), 1)
    total_px = HEADER_PX + n * ROW_HEIGHT_PX + FOOTER_PX
    fig_w = WIDTH_PX / DPI
    fig_h = total_px / DPI

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    def _yc(row_idx: int) -> float:
        row_top = 1.0 - (HEADER_PX + row_idx * ROW_HEIGHT_PX) / total_px
        row_bot = 1.0 - (HEADER_PX + (row_idx + 1) * ROW_HEIGHT_PX) / total_px
        return (row_top + row_bot) / 2

    def _yt(fraction: float = 0.5) -> float:
        return 1.0 - HEADER_PX / total_px * (1.0 - fraction)

    ax.add_patch(mpatches.FancyBboxPatch(
        (0.0, 1.0 - HEADER_PX / total_px), 1.0, HEADER_PX / total_px,
        boxstyle="square,pad=0", linewidth=0, facecolor=_HEADER_BG,
        transform=ax.transAxes, clip_on=False,
    ))
    ax.text(0.015, _yt(0.70), title,
            ha="left", va="center", color=_TITLE_COL,
            fontsize=11, fontweight="bold", transform=ax.transAxes)
    ax.text(0.015, _yt(0.25),
            "Findings without a confirmed timestamp — not placed on the timeline",
            ha="left", va="center", color=_SUBLABEL, fontsize=8,
            transform=ax.transAxes)

    ax.plot([0, 1], [1.0 - HEADER_PX / total_px, 1.0 - HEADER_PX / total_px],
            color=_DIVIDER, linewidth=1.0, transform=ax.transAxes, clip_on=False)

    for i, ev in enumerate(events):
        y_bot = 1.0 - (HEADER_PX + (i + 1) * ROW_HEIGHT_PX) / total_px
        y_top = 1.0 - (HEADER_PX + i * ROW_HEIGHT_PX) / total_px
        y_ctr = _yc(i)

        if i % 2 == 1:
            ax.add_patch(mpatches.FancyBboxPatch(
                (0.0, y_bot), 1.0, y_top - y_bot,
                boxstyle="square,pad=0", linewidth=0, facecolor=_ROW_ALT,
                transform=ax.transAxes, clip_on=False,
            ))
        ax.plot([0, 1], [y_bot, y_bot],
                color=_DIVIDER, linewidth=0.4, alpha=0.35,
                transform=ax.transAxes, clip_on=False)

        severity = ev.get("severity", "info").lower()
        module   = ev.get("module", "")
        ax.text(0.01, y_ctr, f"[{severity.upper()}]",
                ha="left", va="center",
                color=_SEVERITY_COLOR.get(severity, "#90A4AE"),
                fontsize=6.5, fontweight="bold", transform=ax.transAxes)
        ax.text(0.090, y_ctr, ev.get("description", ""),
                ha="left", va="center", color=_LABEL, fontsize=8,
                transform=ax.transAxes)
        if module:
            ax.text(MOD_X, y_ctr, f"[{module}]",
                    ha="right", va="center", color=_module_color(module),
                    fontsize=7, fontweight="bold", transform=ax.transAxes)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout(pad=0)
    fig.savefig(str(output_path), dpi=DPI, bbox_inches="tight",
                facecolor=_BG, edgecolor="none")
    plt.close(fig)
    return output_path


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def _paginate_and_render(
    ev_list: list[dict],
    output_dir: Path,
    case_id: str,
    slug: str,
    title: str,
) -> list[Path]:
    """Sort timed events, paginate to PAGE_MAX_EVENTS, render each page."""
    timed = sorted(
        [(dt, ev) for ev in ev_list if (dt := _parse_ts(ev.get("timestamp", ""))) is not None],
        key=lambda x: x[0],
    )
    ordered = [ev for _, ev in timed]

    if not ordered:
        ph = output_dir / f"{case_id}_timeline_{slug}_p1.png"
        _render_swimlane_page([], 1, 1, title, ph, None)
        return [ph]

    pages = [ordered[i:i + PAGE_MAX_EVENTS]
             for i in range(0, len(ordered), PAGE_MAX_EVENTS)]
    total = len(pages)

    all_dts = [_parse_ts(ev["timestamp"]) for _, ev in timed]
    fmt = "%Y-%m-%d %H:%M UTC"
    tr  = (min(all_dts).strftime(fmt), max(all_dts).strftime(fmt))  # type: ignore[union-attr]

    out_paths: list[Path] = []
    for pg, page_events in enumerate(pages, start=1):
        out = output_dir / f"{case_id}_timeline_{slug}_p{pg}.png"
        page_title = f"{title} — Page {pg}/{total}" if total > 1 else title
        _render_swimlane_page(page_events, pg, total, page_title, out, tr)
        out_paths.append(out)

    return out_paths


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_attacker_timeline(
    events: list[dict],
    output_dir: Path,
    case_id: str,
) -> list[Path]:
    """Paginated vertical swimlane PNGs for attacker events (from parse_events()).

    Untimed events are rendered in a separate _unconfirmed.png plain table.
    Returns all generated PNG paths (timed pages first, then unconfirmed if any).
    """
    output_dir = Path(output_dir)
    timed   = [ev for ev in events if ev.get("timestamp")]
    untimed = [ev for ev in events if not ev.get("timestamp")]

    out = _paginate_and_render(timed, output_dir, case_id, "attacker",
                               "Attacker Perspective Timeline")

    if untimed:
        uc = output_dir / f"{case_id}_timeline_attacker_unconfirmed.png"
        _render_unconfirmed_table(untimed, uc,
                                  "Attacker Perspective — Unconfirmed Findings")
        out.append(uc)

    return out


def generate_defender_timeline(
    steps: list[dict],
    output_dir: Path,
    case_id: str,
) -> list[Path]:
    """Paginated vertical swimlane PNGs for analyst investigation steps."""
    output_dir = Path(output_dir)
    ev_list = [_step_to_event(s) for s in steps]
    return _paginate_and_render(ev_list, output_dir, case_id, "defender",
                                "Defender Perspective Timeline (Analyst Steps)")


def generate_combined_timeline(
    events: list[dict],
    steps: list[dict],
    output_dir: Path,
    case_id: str,
) -> list[Path]:
    """Paginated PNG for critical+high attacker events merged with all defender steps."""
    output_dir = Path(output_dir)
    high_attacker = [ev for ev in events
                     if ev.get("severity", "").lower() in ("critical", "high")
                     and ev.get("timestamp")]
    all_defender = [_step_to_event(s) for s in steps if s.get("timestamp")]
    combined = high_attacker + all_defender
    return _paginate_and_render(combined, output_dir, case_id, "combined",
                                "Combined Key Events Timeline")


def generate_timeline_html(
    events: list[dict],
    steps: list[dict],
    output_dir: Path,
    case_id: str,
) -> Path:
    """Self-contained interactive HTML with three Plotly subplots.

    Falls back to a stub HTML if plotly is not installed.
    """
    output_dir  = Path(output_dir)
    output_path = output_dir / f"{case_id}_timeline.html"

    try:
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots
    except ImportError:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            "<html><body><p>Interactive timeline unavailable — "
            "install plotly: <code>pip install plotly</code></p></body></html>",
            encoding="utf-8",
        )
        return output_path

    def _scatter(ev_list: list[dict], label: str) -> go.Scatter:
        pts = []
        for i, ev in enumerate(ev_list):
            dt = _parse_ts(ev.get("timestamp", "") or "")
            if dt is None:
                continue
            sev    = ev.get("severity", "info").lower()
            mod    = ev.get("module", "")
            desc   = ev.get("description", "")
            src    = ev.get("source_detail", "")
            pts.append({
                "x":    dt.isoformat(),
                "y":    i,
                "text": f"{sev.upper()}: {desc[:55]}",
                "hover": (
                    f"<b>{sev.upper()}</b> [{mod}]<br>"
                    f"<b>Time:</b> {ev.get('timestamp')}<br>"
                    f"<b>Event:</b> {desc}<br>"
                    f"{'<b>Source:</b> ' + src if src else ''}"
                ),
                "size":  _SEVERITY_SIZE.get(sev, 5) * 2,
                "color": _module_color(mod),
                "ring":  3 if sev == "critical" else 0,
            })
        if not pts:
            return go.Scatter(name=label, x=[], y=[], mode="markers")
        return go.Scatter(
            name=label,
            x=[p["x"] for p in pts],
            y=[p["y"] for p in pts],
            mode="markers+text",
            text=[p["text"] for p in pts],
            textposition="middle right",
            hovertemplate="%{customdata}<extra></extra>",
            customdata=[p["hover"] for p in pts],
            marker=dict(
                size=[p["size"] for p in pts],
                color=[p["color"] for p in pts],
                line=dict(width=[p["ring"] for p in pts], color="white"),
            ),
        )

    timed_att = [ev for ev in events if ev.get("timestamp")]
    def_evts  = [_step_to_event(s) for s in steps if s.get("timestamp")]
    combined  = (
        [ev for ev in events
         if ev.get("severity", "").lower() in ("critical", "high") and ev.get("timestamp")]
        + [_step_to_event(s) for s in steps if s.get("timestamp")]
    )

    fig = make_subplots(
        rows=3, cols=1,
        subplot_titles=[
            "Attacker Perspective",
            "Defender Perspective (Analyst Steps)",
            "Combined Key Events (Critical + High)",
        ],
        vertical_spacing=0.10,
        shared_xaxes=False,
    )
    fig.add_trace(_scatter(timed_att, "Attacker"), row=1, col=1)
    fig.add_trace(_scatter(def_evts,  "Defender"), row=2, col=1)
    fig.add_trace(_scatter(combined,  "Combined"), row=3, col=1)

    fig.update_layout(
        height=1050,
        paper_bgcolor=_BG,
        plot_bgcolor=_HEADER_BG,
        font=dict(color="white", family="monospace, sans-serif"),
        title=dict(text=f"Investigation Timelines — {case_id}", font=dict(size=14)),
        showlegend=False,
    )
    for i in range(1, 4):
        fig.update_yaxes(autorange="reversed", showticklabels=False,
                         gridcolor=_DIVIDER, zeroline=False, row=i, col=1)
        fig.update_xaxes(gridcolor=_DIVIDER, row=i, col=1)

    output_dir.mkdir(parents=True, exist_ok=True)
    fig.write_html(str(output_path), include_plotlyjs="cdn", full_html=True)
    return output_path


def generate_timeline_png(
    steps: list[dict],
    output_path: Path,
    title: str = "Investigation Timeline",
    **kwargs: Any,
) -> Path:
    """Backward-compatible shim — generates defender timeline, copies page 1 to output_path."""
    output_path = Path(output_path)
    case_id = output_path.stem.split("_timeline")[0]
    pages = generate_defender_timeline(steps, output_path.parent, case_id)
    if pages and pages[0].exists() and pages[0] != output_path:
        shutil.copy2(str(pages[0]), str(output_path))
    return output_path


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from research_notes import parse_steps, parse_events  # type: ignore[import]

    if len(sys.argv) < 3:
        print("Usage: python3 generate_timeline.py <case_id> <output_dir> [notes_dir]")
        sys.exit(1)

    _case_id   = sys.argv[1]
    _out_dir   = Path(sys.argv[2])
    _notes_dir = sys.argv[3] if len(sys.argv) > 3 else None

    _steps  = parse_steps(_case_id, _notes_dir)
    _events = parse_events(_case_id, _notes_dir)
    print(f"Loaded {len(_steps)} steps, {len(_events)} events")

    _out_dir.mkdir(parents=True, exist_ok=True)
    _a = generate_attacker_timeline(_events, _out_dir, _case_id)
    _d = generate_defender_timeline(_steps,  _out_dir, _case_id)
    _c = generate_combined_timeline(_events, _steps, _out_dir, _case_id)
    _h = generate_timeline_html(_events, _steps, _out_dir, _case_id)

    for p in _a + _d + _c + [_h]:
        size = p.stat().st_size if p.exists() else 0
        print(f"  {'OK' if size else 'MISSING'}: {p.name} ({size:,} bytes)")
