import os
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

requests.packages.urllib3.disable_warnings()  # type: ignore

STATE_FILE = "/opt/soar/ticketing/state_indexer.json"


# ---------- Helpers ----------
def adf_from_text(text: str) -> Dict[str, Any]:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        lines = ["(sin descripción)"]
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": ln}]} for ln in lines],
    }


def parse_ts(ts: str) -> datetime:
    """
    Parse robusto para timestamps típicos en Wazuh/OpenSearch:
    - 2026-02-27T22:49:56.942Z
    - 2026-02-27T22:49:56.942+0000
    - 2026-02-27T22:49:56.942+00:00
    """
    if not ts:
        return datetime.now(timezone.utc)

    s = ts.strip()

    # Z -> +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    # +0000 -> +00:00
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m and ":" not in m.group(0):
        s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return {"processed_ids": []}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"processed_ids": []}


def save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# ---------- Jira ----------
def jira_create_issue(summary: str, description: str, issuetype: str) -> str:
    jira_domain = os.getenv("JIRA_DOMAIN", "").strip()
    jira_project_key = os.getenv("JIRA_PROJECT_KEY", "").strip()
    jira_email = os.getenv("JIRA_EMAIL", "").strip()
    jira_token = os.getenv("JIRA_TOKEN", "").strip()

    if not all([jira_domain, jira_project_key, jira_email, jira_token]):
        raise RuntimeError("Faltan variables Jira en .env (JIRA_DOMAIN/JIRA_PROJECT_KEY/JIRA_EMAIL/JIRA_TOKEN).")

    url = f"https://{jira_domain}/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": jira_project_key},
            "summary": summary,
            "description": adf_from_text(description),
            "issuetype": {"name": issuetype},
        }
    }

    r = requests.post(
        url,
        auth=(jira_email, jira_token),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json=payload,
        timeout=25,
    )

    if r.status_code not in (200, 201):
        raise RuntimeError(f"Jira error {r.status_code}: {r.text}")

    return r.json().get("key", "")


# ---------- Indexer ----------
def indexer_search(indexer_url: str, index_pattern: str, user: str, pwd: str, verify_ssl: bool,
                  time_field: str, lookback_minutes: int, agent_name: Optional[str],
                  min_level: Optional[int], rule_id: Optional[str], size: int = 200) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(minutes=lookback_minutes)).isoformat()

    filters: List[Dict[str, Any]] = [{"range": {time_field: {"gte": gte}}}]
    if agent_name:
        filters.append({"term": {"agent.name": agent_name}})
    if min_level is not None and min_level > 0:
        filters.append({"range": {"rule.level": {"gte": min_level}}})
    if rule_id:
        filters.append({"term": {"rule.id": rule_id}})

    query = {
        "size": size,
        "sort": [{time_field: {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
    }

    url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
    r = requests.get(
        url,
        auth=(user, pwd),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json=query,
        verify=verify_ssl,
        timeout=25,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Indexer search error {r.status_code}: {r.text}")

    return r.json().get("hits", {}).get("hits", [])


def pick_time_field(indexer_url: str, index_pattern: str, user: str, pwd: str, verify_ssl: bool) -> str:
    for tf in ["timestamp", "@timestamp"]:
        try:
            _ = indexer_search(indexer_url, index_pattern, user, pwd, verify_ssl, tf, 1440, None, None, None, size=1)
            return tf
        except RuntimeError as e:
            msg = str(e)
            if "No mapping found for" in msg or "search_phase_execution_exception" in msg:
                continue
            raise
    return "timestamp"


# ---------- Correlación ----------
def extract_fields(src: Dict[str, Any]) -> Tuple[str, str, str, str, str, str]:
    """
    Devuelve: agent, rule_id, rule_desc, level, src_ip, target_user
    Intenta sacar IP y user de campos típicos de Windows.
    """
    agent = (src.get("agent") or {}).get("name", "unknown-agent")
    rule = src.get("rule") or {}
    rule_id = str(rule.get("id", "unknown"))
    rule_desc = rule.get("description", "Wazuh alert")
    level = str(rule.get("level", "unknown"))

    data = src.get("data") or {}
    # IP origen típica
    src_ip = data.get("srcip") or data.get("src_ip") or data.get("sourceIp") or ""

    # En Windows EventChannel suele estar aquí:
    win = data.get("win") or {}
    eventdata = (win.get("eventdata") or {})
    if not src_ip:
        src_ip = eventdata.get("ipAddress") or ""

    target_user = eventdata.get("targetUserName") or ""
    event_id = (src.get("win") or {}).get("system", {}).get("eventID") or ""
    failure_reason = eventdata.get("failureReason") or ""

    # devolvemos también event_id y failure_reason como “extra”
    return agent, rule_id, rule_desc, level, src_ip, target_user


def main() -> int:
    load_dotenv()

    # Indexer config
    indexer_url = os.getenv("INDEXER_URL", "").strip()
    indexer_user = os.getenv("INDEXER_USER", "").strip()
    indexer_pass = os.getenv("INDEXER_PASS", "").strip()
    verify_ssl = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"
    index_pattern = os.getenv("INDEXER_INDEX", "wazuh-alerts-*").strip()

    if not all([indexer_url, indexer_user, indexer_pass]):
        print("ERROR: faltan INDEXER_URL/INDEXER_USER/INDEXER_PASS en .env")
        return 2

    # Filtros base
    agent_filter = os.getenv("WAZUH_AGENT", "").strip() or None
    rule_id_filter = os.getenv("WAZUH_RULE_ID", "").strip() or None
    min_level = int(os.getenv("WAZUH_MIN_LEVEL", "0"))
    lookback = int(os.getenv("LOOKBACK_MINUTES", "240"))

    # Correlación
    window_min = int(os.getenv("CORRELATION_WINDOW_MINUTES", "10"))
    threshold = int(os.getenv("CORRELATION_THRESHOLD", "2"))
    max_events_desc = int(os.getenv("MAX_EVENTS_IN_DESCRIPTION", "10"))
    max_tickets_run = int(os.getenv("MAX_TICKETS_PER_RUN", "5"))

    # Jira
    jira_type = os.getenv("JIRA_ISSUE_TYPE", "Incident").strip()

    # Deduplicación por alert _id
    state = load_state()
    processed = set(state.get("processed_ids", []))

    time_field = pick_time_field(indexer_url, index_pattern, indexer_user, indexer_pass, verify_ssl)

    hits = indexer_search(
        indexer_url=indexer_url,
        index_pattern=index_pattern,
        user=indexer_user,
        pwd=indexer_pass,
        verify_ssl=verify_ssl,
        time_field=time_field,
        lookback_minutes=lookback,
        agent_name=agent_filter,
        min_level=min_level if min_level > 0 else None,
        rule_id=rule_id_filter,
        size=300,
    )

    if not hits:
        print("No hay alertas (según búsqueda). OK.")
        return 0

    # Solo consideramos eventos dentro de la ventana de correlación
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_min)

    # Agrupar por (agent, rule_id, src_ip, target_user)
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for h in hits:
        alert_id = h.get("_id")
        if not alert_id:
            continue

        src = h.get("_source", {})
        ts_raw = src.get(time_field) or src.get("@timestamp") or ""
        dt = parse_ts(str(ts_raw))

        # Nos quedamos con lo que está dentro de la ventana
        if dt < window_start:
            continue

        # No descartamos por processed aquí, porque queremos poder llegar al threshold.
        agent, rule_id, rule_desc, level, src_ip, target_user = extract_fields(src)

        key = f"{agent}|{rule_id}|{src_ip or 'noip'}|{target_user or 'nouser'}"
        groups.setdefault(key, []).append(h)

    if not groups:
        print("No hay alertas que cumplan el filtro. OK.")
        return 0

    created_keys: List[str] = []
    tickets_created = 0

    for key, items in groups.items():
        # Ordenar por timestamp asc
        items_sorted = sorted(
            items,
            key=lambda x: parse_ts(str((x.get("_source", {}) or {}).get(time_field) or (x.get("_source", {}) or {}).get("@timestamp") or "")),
        )

        # Solo contamos las no procesadas para decidir ticket,
        # pero si creamos ticket, marcamos todas las de la ventana como procesadas
        unprocessed = [it for it in items_sorted if it.get("_id") not in processed]

        if len(items_sorted) < threshold:
            continue  # no llega al umbral en la ventana

        # Construir ticket
        src0 = items_sorted[0].get("_source", {})
        agent, rule_id, rule_desc, level, src_ip, target_user = extract_fields(src0)

        first_ts = str(src0.get(time_field) or src0.get("@timestamp") or "")
        last_src = items_sorted[-1].get("_source", {})
        last_ts = str(last_src.get(time_field) or last_src.get("@timestamp") or "")

        summary = f"[Wazuh] {len(items_sorted)}x {rule_desc} | {agent} | {src_ip or 'sin IP'}"
        if target_user:
            summary += f" | user={target_user}"

        lines = [
            f"INCIDENTE CORRELADO (ventana {window_min} min, umbral {threshold})",
            f"agent: {agent}",
            f"rule_id: {rule_id}",
            f"rule_level: {level}",
            f"rule_desc: {rule_desc}",
            f"src_ip: {src_ip or '(no disponible)'}",
            f"target_user: {target_user or '(no disponible)'}",
            f"rango: {first_ts}  ->  {last_ts}",
            "",
            f"Eventos incluidos en la ventana (máx {max_events_desc}):",
        ]

        for it in items_sorted[:max_events_desc]:
            _id = it.get("_id")
            s = it.get("_source", {}) or {}
            t = str(s.get(time_field) or s.get("@timestamp") or "")
            lines.append(f"- {t} | indexer_id={_id}")

        if len(items_sorted) > max_events_desc:
            lines.append(f"... ({len(items_sorted) - max_events_desc} más)")

        # Crear ticket
        issue_key = jira_create_issue(summary, "\n".join(lines), issuetype=jira_type)
        created_keys.append(issue_key)

        # Marcar procesadas TODAS las de esa ventana/grupo
        for it in items_sorted:
            if it.get("_id"):
                processed.add(it["_id"])

        tickets_created += 1
        if tickets_created >= max_tickets_run:
            break

    state["processed_ids"] = list(processed)[-2000:]
    save_state(state)

    if created_keys:
        print("Tickets creados:", ", ".join(created_keys))
    else:
        print("No hay alertas que cumplan el filtro. OK.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
