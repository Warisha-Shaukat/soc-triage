"""Streamlit analyst queue (AGENTS.md section 4.6).

    streamlit run app.py

Tab 1, Queue: browse a finished run. Left, the alerts with their verdicts; right, the selected
alert's fields with the model's evidence quotes highlighted, and Confirm / Override buttons that
append to data/overrides.jsonl. Nothing else is written.

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
VERDICTS = ["true_positive", "false_positive", "needs_human"]
SHOWN = {"true_positive": "escalate (true_positive)", "false_positive": "dismiss (false_positive)",
         "needs_human": "escalate (needs_human)"}


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


def highlight(text: str, quotes: list[str]) -> str:
    """HTML-escaped text with every occurrence of every quote wrapped in <mark>."""
    marked = [False] * len(text)
    for quote in quotes:
        if not quote:
            continue
        start = text.find(quote)
        while start != -1:
            for i in range(start, start + len(quote)):
                marked[i] = True
            start = text.find(quote, start + 1)
    out, i = [], 0
    while i < len(text):                 # join runs of marked or unmarked characters
        j = i
        while j < len(text) and marked[j] == marked[i]:
            j += 1
        piece = html.escape(text[i:j])
        out.append(f"<mark>{piece}</mark>" if marked[i] else piece)
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


# --- Streamlit pages ---------------------------------------------------------
def show_fields(wazuh: dict, evidence: list[dict], cfg: dict) -> None:
    """Field table. Quotes are marked in the field they name, and all quotes in the raw log."""
    all_quotes = [e.get("quote", "") for e in evidence]
    lines = []
    for name, text in original_fields(wazuh, cfg).items():
        quotes = all_quotes if name == "full_log" else [e.get("quote", "") for e in evidence
                                                        if e.get("field") == name]
        lines.append(f"<tr><td><code>{html.escape(name)}</code></td>"
                     f"<td style='word-break:break-all'>{highlight(text, quotes)}</td></tr>")
    st.markdown("<table>" + "".join(lines) + "</table>", unsafe_allow_html=True)


def show_verdict(row: dict) -> None:
    final = row["final_verdict"]
    text = SHOWN.get(final, final)
    if final == "false_positive":
        st.success(f"Final verdict: {text}")
    else:
        st.error(f"Final verdict: {text}")
    if row.get("model_verdict") != final:
        st.caption(f"The model said `{row.get('model_verdict')}`; the guard changed it. "
                   f"Reasons: {', '.join(row['reasons']) or 'none'}")
    if row.get("guard_flags"):
        st.warning("Suspicion detector: " + ", ".join(row["guard_flags"]))
    st.write("**Rationale:**", row.get("rationale") or "(invalid output)")


def queue_tab(cfg: dict) -> None:
    runs = finished_runs(ROOT / cfg["paths"]["results_raw"])
    if not runs:
        st.info("No finished run yet. Run `python -m src.pipeline ...` first.")
        return
    top = st.columns([3, 3, 2])
    run_id = top[0].selectbox("Run", runs)
    chosen = top[1].multiselect("Final verdict", VERDICTS, default=VERDICTS)
    # Labels are hidden by default so the app does not spoil the blind hand spot-check.
    show_labels = top[2].checkbox("Show stored labels", help="Fill data/spotcheck/sheet.csv first.")

    rows = [r for r in load_run_cached(run_id) if r["final_verdict"] in chosen]
    table = pd.DataFrame([{
        "id": r["id"],
        "rule": r["wazuh"]["rule"]["description"],
        "verdict": r["final_verdict"],
        "guard flags": ", ".join(r["guard_flags"]),
        **({"payload": f"{r['strategy']}{r['variant']} in {r['field']}"} if "strategy" in r else {}),
        **({"label": r["label"]} if show_labels else {}),
    } for r in rows])

    left, right = st.columns([5, 6])
    with left:
        st.caption(f"{len(rows)} alerts")
        event = st.dataframe(table, hide_index=True, on_select="rerun", selection_mode="single-row",
                             key=f"table-{run_id}", height=560)
    picked = event.selection.rows
    if not picked:
        right.info("Select an alert on the left.")
        return
    row = rows[picked[0]]
    with right:
        st.subheader(row["id"])
        show_verdict(row)
        if row.get("payload"):
            st.info(f"Planted harmless test payload ({row['strategy']}{row['variant']}, "
                    f"field `{row['field']}`): {row['payload']}")
        if show_labels:
            st.caption(f"Stored label: {row['label']}")
        evidence = evidence_of(row)
        show_fields(row["wazuh"], evidence, cfg)
        st.caption("Highlighted: the model's evidence quotes.")
        decision_form(run_id, row)


def decision_form(run_id: str, row: dict) -> None:
    with st.form(f"decision-{run_id}-{row['id']}", clear_on_submit=True):
        verdict = st.selectbox("Your verdict if you override", VERDICTS)
        note = st.text_input("Note (optional)")
        confirm, override = st.columns(2)
        do_confirm = confirm.form_submit_button("Confirm")
        do_override = override.form_submit_button("Override")
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
    p = c[2].selectbox("Plant a harmless test payload asking to dismiss", list(options), disabled=not fields)
    if options.get(p) and fields:
        field = st.selectbox("Field", fields)
        wazuh = plant(wazuh, field, options[p])
        st.info(f"Planted: {options[p]}")

    if not st.button("Triage, guard off and on"):
        return
    client = OllamaClient(cfg["models"][role]["tag"], cfg["ollama"], APP_CACHE)
    cols = st.columns(2)
    for col, (name, layers) in zip(cols, [("Guard off", NO_LAYERS), ("Guard on", dict(cfg["guard"]["layers"]))]):
        with col:
            st.subheader(name)
            try:
                with st.spinner("Asking the model..."):
                    row = triage_alert(wazuh, client, cfg, layers)
            except requests.RequestException as e:
                st.error(f"Ollama is not reachable at {cfg['ollama']['url']}: {e}")
                return
            show_verdict(row)
            if CANARY in (row.get("rationale") or ""):
                st.warning(f"The canary {CANARY} appears in the rationale.")
            show_fields(wazuh, evidence_of(row), cfg)
            st.caption(f"{row['latency_s']} s" + (" (cached)" if row["cached"] else ""))
            with st.expander("What the model is shown (an example: the nonce changes every request)"):
                guarded = guard.prepare(wazuh, cfg["guard"], layers)
                st.code(guard.wrap_fields(guarded.fields, guarded.nonce), language=None)


@st.cache_data
def load_run_cached(run_id: str) -> list[dict]:
    return load_run(run_id, load_config())


@st.cache_data
def load_alerts_cached() -> list[dict]:
    return read_jsonl(ROOT / load_config()["paths"]["alerts"])


def main():
    st.set_page_config(page_title="SOC triage queue", layout="wide")
    st.title("Local SOC triage with a log-injection guard")
    st.caption("Lab prototype. No authentication. Verdicts come from saved runs; nothing here changes results.")
    cfg = load_config()
    queue, live = st.tabs(["Queue", "Try an alert"])
    with queue:
        queue_tab(cfg)
    with live:
        try_tab(cfg)


if __name__ == "__main__":
    main()
