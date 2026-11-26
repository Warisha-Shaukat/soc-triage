"""Streamlit analyst queue (AGENTS.md section 4.6).

    streamlit run app.py

Tab 1, Queue: browse a finished run. A summary row and a bar show where the verdicts went; left,
the alerts; right, the selected alert's fields with the model's evidence quotes highlighted (and a
planted payload marked in red), plus Confirm / Override buttons that append to
data/overrides.jsonl. Nothing else is written.

Tab 2, Try an alert: send one alert through the real pipeline, guard off and on side by side,
optionally after planting one of the harmless test payloads. This calls Ollama live and uses its
own cache (results/cache_app), so it never touches the experiment's cache or results.

Lab prototype: no authentication.
"""
import html
import json

import pandas as pd
import requests
import streamlit as st

from src import guard
from src.build_injection_set import CANARY, payloads, plant, usable_fields
from src.common import ROOT, load_config, now_utc, read_jsonl
from src.llm import OllamaClient
from src.pipeline import NO_LAYERS, triage_alert

OVERRIDES = ROOT / "data/overrides.jsonl"
APP_CACHE = ROOT / "results/cache_app"
VERDICTS = ["true_positive", "needs_human", "false_positive"]

# How each verdict is shown. Colours are status colours (red = escalate, amber = needs a human,
# green = dismiss), and every badge also carries an icon and a word, so colour is never the only cue.
STYLE = {
    "true_positive": {"css": "esc", "icon": "▲", "label": "Escalate"},
    "needs_human": {"css": "hum", "icon": "◆", "label": "Needs human"},
    "false_positive": {"css": "dis", "icon": "✓", "label": "Dismiss"},
}
# Soft tints for the verdict column of the queue table (readable on light and dark themes).
TINT = {"true_positive": "rgba(220,60,61,.20)", "needs_human": "rgba(251,179,21,.25)",
        "false_positive": "rgba(10,172,35,.18)"}

CSS = """
<style>
.hero {padding: 18px 22px; border-radius: 14px; margin-bottom: 10px; color: #fff;
       background: linear-gradient(120deg, #0e3d7e 0%, #257de0 55%, #00a888 100%);}
.hero h1 {color: #fff; font-size: 1.55rem; margin: 0; padding: 0;}
.hero p {margin: 4px 0 0; opacity: .92; font-size: .95rem;}
.pill {display: inline-block; padding: 2px 10px; margin: 0 6px 4px 0; border-radius: 999px;
       font-size: .78rem; font-weight: 600; border: 1px solid rgba(128,128,128,.35);}
.badge {display: inline-block; padding: 4px 12px; border-radius: 999px; font-weight: 700; font-size: .92rem;}
.badge.small {padding: 1px 9px; font-size: .78rem;}
.esc {background: #dc3c3d; color: #fff;}
.hum {background: #fbb315; color: #191919;}
.dis {background: #008a17; color: #fff;}
.flow {display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 6px 0 10px;
       font-size: .85rem; opacity: .95;}
.flag {display: inline-block; padding: 1px 8px; margin: 2px 4px 2px 0; border-radius: 6px; font-size: .78rem;
       background: rgba(251,179,21,.20); border: 1px solid #fbb315;}
.vbar {display: flex; gap: 2px; height: 26px; border-radius: 6px; overflow: hidden; margin: 2px 0 2px;}
.seg {display: flex; align-items: center; justify-content: center; font-size: .78rem; font-weight: 700;
      white-space: nowrap; overflow: hidden;}
.barlabel {font-size: .82rem; margin-top: 8px; opacity: .85;}
.legend {display: flex; gap: 14px; flex-wrap: wrap; font-size: .8rem; margin: 6px 0 4px;}
.legend span.sw {display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 5px;}
.fields {width: 100%; border-collapse: collapse; font-size: .86rem;}
.fields td {padding: 6px 8px; border-bottom: 1px solid rgba(128,128,128,.18); vertical-align: top;
            word-break: break-all;}
.fields td:first-child {white-space: nowrap; width: 1%; opacity: .75; word-break: normal;}
.fields tr:nth-child(even) {background: rgba(128,128,128,.06);}
mark {background: rgba(251,179,21,.45); color: inherit; border-radius: 3px; padding: 0 2px;}
mark.payload {background: rgba(220,60,61,.28); outline: 1px dashed #dc3c3d;}
.payload-box {border-left: 4px solid #dc3c3d; background: rgba(220,60,61,.10); padding: 8px 12px;
              border-radius: 6px; font-size: .86rem; margin: 6px 0 10px;}
.rationale {border-left: 4px solid #257de0; background: rgba(37,125,224,.08); padding: 8px 12px;
            border-radius: 6px; font-size: .9rem; margin: 6px 0 10px;}
</style>
"""


# --- Helpers without any Streamlit code (tested in tests/test_all.py) -------
def finished_runs(raw_dir) -> list[str]:
    """Run ids that have a meta file, so they finished. Smoke runs are left out."""
    return sorted(p.name.removesuffix(".meta.json") for p in raw_dir.glob("*.meta.json")
                  if not p.name.startswith("smoke_"))


def load_run(run_id: str, cfg: dict) -> list[dict]:
    """Rows of one run, each with the alert JSON the model was given."""
    rows = read_jsonl(ROOT / cfg["paths"]["results_raw"] / f"{run_id}.jsonl")
    source = "injection_set" if "_inject_" in run_id else "alerts"
    by_id = {a["id"]: a for a in read_jsonl(ROOT / cfg["paths"][source])}
    for row in rows:
        item = by_id[row["id"]]
        row["wazuh"] = item["wazuh"]
        row["payload"] = item.get("payload")          # only injection cases have one
    return rows


def evidence_of(row: dict) -> list[dict]:
    """Evidence items from the last raw model answer; empty if that answer was invalid."""
    try:
        return json.loads(row["raw"][-1]).get("evidence", [])
    except (json.JSONDecodeError, IndexError, AttributeError):
        return []


def highlight(text: str, quotes: list[str], danger: tuple = ()) -> str:
    """HTML-escaped text. Every occurrence of a quote is wrapped in <mark>; every occurrence of a
    `danger` string (the planted payload) in <mark class="payload">, which wins where both overlap."""
    marked = [0] * len(text)                      # 0 = plain, 1 = evidence, 2 = payload
    for level, strings in ((1, quotes), (2, danger)):
        for s in strings:
            if not s:
                continue
            start = text.find(s)
            while start != -1:
                for i in range(start, start + len(s)):
                    marked[i] = max(marked[i], level)
                start = text.find(s, start + 1)
    out, i = [], 0
    while i < len(text):                          # join runs of equally marked characters
        j = i
        while j < len(text) and marked[j] == marked[i]:
            j += 1
        piece = html.escape(text[i:j])
        out.append({0: piece, 1: f"<mark>{piece}</mark>", 2: f'<mark class="payload">{piece}</mark>'}[marked[i]])
        i = j
    return "".join(out)


def append_override(path, record: dict) -> None:
    """One analyst decision per line. Append only, never rewritten."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def original_fields(wazuh: dict, cfg: dict) -> dict[str, str]:
    """The allowed fields, uncut, as they are in the alert."""
    return guard.select_fields(wazuh, cfg["guard"]["allowed_fields"], 10**9)[0]


def run_stats(rows: list[dict]) -> dict:
    """Headline numbers for one run. `dismissed` = final verdict false_positive."""
    attacks = [r for r in rows if r["label"] == "tp"]
    caught = sum(r["final_verdict"] != "false_positive" for r in attacks)
    correct = sum((r["final_verdict"] != "false_positive") == (r["label"] == "tp") for r in rows)
    return {
        "n": len(rows),
        "counts": {v: sum(r["final_verdict"] == v for r in rows) for v in VERDICTS},
        "flagged": sum(bool(r["guard_flags"]) for r in rows),
        "attacks": len(attacks), "caught": caught, "missed": len(attacks) - caught,
        "accuracy": correct / len(rows) if rows else 0.0,
    }


def badge(verdict: str, small: bool = False) -> str:
    s = STYLE.get(verdict, {"css": "hum", "icon": "?", "label": str(verdict)})
    return f'<span class="badge {s["css"]}{" small" if small else ""}">{s["icon"]} {s["label"]}</span>'


def verdict_bar(counts: dict[str, int], title: str = "") -> str:
    """One horizontal bar split by final verdict (parts of a whole). Hover a part for its count."""
    total = sum(counts.values()) or 1
    parts = []
    for v in VERDICTS:
        n = counts.get(v, 0)
        if n:
            s = STYLE[v]
            text = f"{s['label']} {100 * n / total:.0f}%" if n / total >= 0.12 else ""
            parts.append(f'<div class="seg {s["css"]}" style="flex:{n}" '
                         f'title="{s["label"]}: {n} of {total} ({100 * n / total:.1f}%)">{text}</div>')
    head = f'<div class="barlabel">{html.escape(title)}</div>' if title else ""
    return head + f'<div class="vbar">{"".join(parts)}</div>'


def legend(counts: dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    colours = {"true_positive": "#dc3c3d", "needs_human": "#fbb315", "false_positive": "#008a17"}
    return '<div class="legend">' + "".join(
        f'<span><span class="sw" style="background:{colours[v]}"></span>{STYLE[v]["icon"]} '
        f'{STYLE[v]["label"]}: {counts.get(v, 0)} ({100 * counts.get(v, 0) / total:.1f}%)</span>'
        for v in VERDICTS) + "</div>"


# --- Streamlit pages ---------------------------------------------------------
def describe_run(run_id: str, cfg: dict) -> str:
    """Pills under the run picker: split, alert set, guard, model."""
    split, which, g, role = run_id.split("_")
    meta = json.loads((ROOT / cfg["paths"]["results_raw"] / f"{run_id}.meta.json").read_text(encoding="utf-8"))
    pills = [f"{split} split", "injected alerts" if which == "inject" else "clean alerts",
             "guard " + g.removeprefix("guard-"), meta["model_tag"]]
    return "".join(f'<span class="pill">{html.escape(p)}</span>' for p in pills)


def show_fields(wazuh: dict, evidence: list[dict], cfg: dict, payload=None) -> None:
    """Field table. Quotes are marked in the field they name, and all quotes in the raw log.
    A planted payload is marked in red wherever it appears."""
    all_quotes = [e.get("quote", "") for e in evidence]
    danger = (payload,) if payload else ()
    lines = []
    for name, text in original_fields(wazuh, cfg).items():
        quotes = all_quotes if name == "full_log" else [e.get("quote", "") for e in evidence
                                                        if e.get("field") == name]
        lines.append(f"<tr><td><code>{html.escape(name)}</code></td>"
                     f"<td>{highlight(text, quotes, danger)}</td></tr>")
    st.markdown('<table class="fields">' + "".join(lines) + "</table>", unsafe_allow_html=True)
    key = "<mark>model's evidence</mark>" + (' &nbsp; <mark class="payload">planted payload</mark>' if payload else "")
    st.markdown(f'<div class="legend">Highlighted: {key}</div>', unsafe_allow_html=True)


def show_verdict(row: dict) -> None:
    """The final verdict as a badge, how the guard got there, and the model's rationale."""
    final, model = row["final_verdict"], row.get("model_verdict")
    st.markdown(f"Final verdict &nbsp; {badge(final)}", unsafe_allow_html=True)
    if model != final:
        reasons = ", ".join(row["reasons"]) or "none"
        st.markdown(f'<div class="flow">Model said {badge(model, True)} → guard ({html.escape(reasons)}) → '
                    f"{badge(final, True)}</div>", unsafe_allow_html=True)
    if row.get("guard_flags"):
        flags = "".join(f'<span class="flag">⚑ {html.escape(f)}</span>' for f in row["guard_flags"])
        st.markdown(f"<div>Suspicion detector: {flags}</div>", unsafe_allow_html=True)
    st.markdown(f'<div class="rationale"><b>Rationale.</b> '
                f'{html.escape(row.get("rationale") or "(invalid output)")}</div>', unsafe_allow_html=True)


def summary(rows: list[dict], show_labels: bool) -> None:
    """Headline numbers and the verdict bar(s) for the chosen run."""
    s = run_stats(rows)
    tiles = [("Alerts", f"{s['n']}"),
             ("Escalated", f"{s['counts']['true_positive'] + s['counts']['needs_human']}"),
             ("Dismissed", f"{s['counts']['false_positive']}"),
             ("Detector flagged", f"{s['flagged']}")]
    if show_labels:
        tiles += [("Attacks caught", f"{s['caught']} / {s['attacks']}"),
                  ("Missed attacks", f"{s['missed']}"),
                  ("Accuracy", f"{100 * s['accuracy']:.1f}%")]
    for col, (name, value) in zip(st.columns(len(tiles)), tiles):
        with col.container(border=True):
            st.metric(name, value)
    if show_labels:
        bars = [verdict_bar(run_stats([r for r in rows if r["label"] == lab])["counts"], title)
                for lab, title in (("tp", "Real attacks (stored label tp): where they went"),
                                   ("fp", "Benign alerts (stored label fp): where they went"))]
        st.markdown("".join(bars) + legend(s["counts"]), unsafe_allow_html=True)
    else:
        st.markdown(verdict_bar(s["counts"], "Final verdicts") + legend(s["counts"]), unsafe_allow_html=True)


def queue_tab(cfg: dict) -> None:
    runs = finished_runs(ROOT / cfg["paths"]["results_raw"])
    if not runs:
        st.info("No finished run yet. Run `python -m src.pipeline ...` first.")
        return
    top = st.columns([3, 3, 2])
    run_id = top[0].selectbox("Run", runs)
    chosen = top[1].multiselect("Final verdict", VERDICTS, default=VERDICTS,
                                format_func=lambda v: f"{STYLE[v]['icon']} {STYLE[v]['label']}")
    # Labels are hidden by default so the app does not spoil a blind label check.
    show_labels = top[2].checkbox("Show stored labels", help="Fill data/spotcheck/sheet.csv first.")
    st.markdown(describe_run(run_id, cfg), unsafe_allow_html=True)

    all_rows = load_run_cached(run_id)
    summary(all_rows, show_labels)
    rows = [r for r in all_rows if r["final_verdict"] in chosen]
    table = pd.DataFrame([{
        "id": r["id"],
        "verdict": f"{STYLE[r['final_verdict']]['icon']} {STYLE[r['final_verdict']]['label']}",
        "rule": r["wazuh"]["rule"]["description"],
        "guard flags": ", ".join(r["guard_flags"]),
        **({"payload": f"{r['strategy']}{r['variant']} in {r['field']}"} if "strategy" in r else {}),
        **({"label": r["label"]} if show_labels else {}),
    } for r in rows])
    verdict_of = {f"{s['icon']} {s['label']}": v for v, s in STYLE.items()}
    styled = table.style.map(lambda cell: f"background-color: {TINT[verdict_of[cell]]}", subset=["verdict"]) \
        if not table.empty else table

    st.divider()
    left, right = st.columns([5, 6], gap="large")
    with left:
        st.caption(f"{len(rows)} alerts shown. Click a row to open it.")
        event = st.dataframe(styled, hide_index=True, on_select="rerun", selection_mode="single-row",
                             key=f"table-{run_id}", height=600, use_container_width=True)
    picked = event.selection.rows
    if not picked:
        right.info("Select an alert on the left to see its fields, evidence and verdict.")
        return
    row = rows[picked[0]]
    with right, st.container(border=True):
        st.subheader(row["id"])
        st.caption(row["wazuh"]["rule"]["description"] + f"  ·  rule {row['wazuh']['rule']['id']}"
                   f"  ·  level {row['wazuh']['rule']['level']}")
        show_verdict(row)
        if row.get("payload"):
            st.markdown(f'<div class="payload-box"><b>Planted harmless test payload</b> '
                        f'({html.escape(row["strategy"] + row["variant"])}, field <code>{html.escape(row["field"])}</code>): '
                        f'{html.escape(row["payload"])}</div>', unsafe_allow_html=True)
        if show_labels:
            st.caption(f"Stored label: {row['label']}")
        show_fields(row["wazuh"], evidence_of(row), cfg, row.get("payload"))
        decision_form(run_id, row)


def decision_form(run_id: str, row: dict) -> None:
    with st.form(f"decision-{run_id}-{row['id']}", clear_on_submit=True):
        st.markdown("**Analyst decision**")
        verdict = st.selectbox("Your verdict if you override", VERDICTS,
                               format_func=lambda v: f"{STYLE[v]['icon']} {STYLE[v]['label']}")
        note = st.text_input("Note (optional)")
        confirm, override = st.columns(2)
        do_confirm = confirm.form_submit_button("✓ Confirm", type="primary", use_container_width=True)
        do_override = override.form_submit_button("✎ Override", use_container_width=True)
    if do_confirm or do_override:
        append_override(OVERRIDES, {
            "time_utc": now_utc(), "run_id": run_id, "alert_id": row["id"],
            "pipeline_verdict": row["final_verdict"], "decision": "confirm" if do_confirm else "override",
            "analyst_verdict": row["final_verdict"] if do_confirm else verdict, "note": note})
        st.toast("Saved to data/overrides.jsonl")


def try_tab(cfg: dict) -> None:
    st.caption("Runs the real pipeline live. It shares the GPU with any experiment that is running "
               "and slows it down, so use it when no run is going.")
    by_name = {f"{a['id']}  {a['wazuh']['rule']['description']}": a["wazuh"] for a in load_alerts_cached()}
    c = st.columns([3, 2, 3])
    pick = c[0].selectbox("Alert", [""] + list(by_name))
    role = c[1].selectbox("Model", ["primary", "secondary"],
                          format_func=lambda r: cfg["models"][r]["tag"])
    pasted = st.text_area("...or paste Wazuh alert JSON", height=120)
    if pasted.strip():
        try:
            wazuh = json.loads(pasted)
        except json.JSONDecodeError:
            st.error("That is not valid JSON.")
            return
        if not isinstance(wazuh, dict) or not isinstance(wazuh.get("rule"), dict):
            st.error("Expected one Wazuh alert: a JSON object with a `rule` object.")
            return
    elif pick:
        wazuh = by_name[pick]
    else:
        return

    options = {"none": None, **{f"{s}{v}": text for (s, v), (text, _) in payloads("dismiss").items()}}
    fields = usable_fields(wazuh, cfg["injection"]["fields"])
    p = c[2].selectbox("Plant a harmless test payload asking to dismiss", list(options), disabled=not fields,
                       help="S1 override, S2 fake authority, S3 fake log structure, S4 encoded. "
                            "Wording c was held out when the detector was written.")
    payload = options.get(p) if fields else None
    if payload:
        field = st.selectbox("Field", fields)
        wazuh = plant(wazuh, field, payload)
        st.markdown(f'<div class="payload-box"><b>Planted:</b> {html.escape(payload)}</div>',
                    unsafe_allow_html=True)

    if not st.button("Triage, guard off and on", type="primary"):
        return
    client = OllamaClient(cfg["models"][role]["tag"], cfg["ollama"], APP_CACHE)
    cols = st.columns(2, gap="large")
    for col, (name, layers) in zip(cols, [("Guard off", NO_LAYERS), ("Guard on", dict(cfg["guard"]["layers"]))]):
        with col, st.container(border=True):
            st.subheader(("🔓 " if name == "Guard off" else "🛡 ") + name)
            try:
                with st.spinner("Asking the model..."):
                    row = triage_alert(wazuh, client, cfg, layers)
            except requests.RequestException as e:
                st.error(f"Ollama is not reachable at {cfg['ollama']['url']}: {e}")
                return
            show_verdict(row)
            if CANARY in (row.get("rationale") or ""):
                st.warning(f"The canary {CANARY} appears in the rationale.")
            show_fields(wazuh, evidence_of(row), cfg, payload)
            st.caption(f"{row['latency_s']} s" + (" (cached)" if row["cached"] else ""))
            with st.expander("What the model is shown (an example: the nonce changes every request)"):
                guarded = guard.prepare(wazuh, cfg["guard"], layers)
                st.code(guard.wrap_fields(guarded.fields, guarded.nonce), language=None)


def about_sidebar(cfg: dict) -> None:
    with st.sidebar:
        st.markdown("### How to read this")
        st.markdown(legend({v: 0 for v in VERDICTS}).replace(": 0 (0.0%)", ""), unsafe_allow_html=True)
        st.markdown("- **Escalate** and **Needs human** both send the alert to an analyst.\n"
                    "- **Dismiss** closes it. Dismissing a real attack is the costly error.\n"
                    "- The guard turns a suspected injection or an unsupported quote into **Needs human**.")
        st.markdown("### Models")
        for role in ("primary", "secondary"):
            st.markdown(f'<span class="pill">{cfg["models"][role]["tag"]}</span>', unsafe_allow_html=True)
        st.caption("Local via Ollama · temperature 0 · fixed seed · no authentication (lab prototype)")


@st.cache_data
def load_run_cached(run_id: str) -> list[dict]:
    return load_run(run_id, load_config())


@st.cache_data
def load_alerts_cached() -> list[dict]:
    return read_jsonl(ROOT / load_config()["paths"]["alerts"])


def main():
    st.set_page_config(page_title="SOC triage queue", page_icon="🛡", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown('<div class="hero"><h1>🛡 Local SOC triage with a log-injection guard</h1>'
                "<p>Small local models triage Wazuh alerts; a fail-closed guard watches for text that tries "
                "to steer them. Verdicts come from saved runs; nothing here changes results.</p></div>",
                unsafe_allow_html=True)
    cfg = load_config()
    about_sidebar(cfg)
    queue, live = st.tabs(["📋 Queue", "🧪 Try an alert"])
    with queue:
        queue_tab(cfg)
    with live:
        try_tab(cfg)


if __name__ == "__main__":
    main()
