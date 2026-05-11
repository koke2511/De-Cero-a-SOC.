import os
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

requests.packages.urllib3.disable_warnings()  # type: ignore

STATE_FILE = "/opt/soar/ticketing/state_indexer.json"

def notify_n8n(payload: Dict[str, Any]) -> None:
    """
    Envía un POST al webhook de n8n para disparar notificaciones (email/telegram).
    Si no hay N8N_WEBHOOK_URL configurada, no hace nada.
    """
    url = os.getenv("N8N_WEBHOOK_URL", "").strip()
    if not url:
        return
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[WARN] No se pudo notificar a n8n: {e}")

def adf_from_text(text: str) -> Dict[str, Any]:
     """Texto plano -> Atlassian Document Format (ADF) para Jira Cloud API v3."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        lines = ["(sin descripción)"]
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": ln}]} for ln in lines],
    }


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

def jira_create_issue(summary: str, description: str, issuetype: str = "Incident") -> str:
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


def get_src_ip_from_alert_source(src: Dict[str, Any]) -> str:
    """
    Extrae IP atacante de diferentes lugares:
    - data.srcip / data.src_ip / data.sourceIp (genérico)
    - data.win.eventdata.ipAddress (Windows EventChannel)
    """
    data = src.get("data") or {}

    # 1) Campos genéricos (a veces existen)
    srcip = data.get("srcip") or data.get("src_ip") or data.get("sourceIp") or ""
    if srcip:
        return str(srcip)

    # 2) Windows EventChannel (muy común en 60122/100501 en tu lab)
    win = data.get("win") or {}
    eventdata = win.get("eventdata") or {}
    ip = eventdata.get("ipAddress") or ""
    return str(ip) if ip else ""

def indexer_search() -> List[Dict[str, Any]]:
    idx_url = os.getenv("INDEXER_URL", "").strip().rstrip("/")
    idx_user = os.getenv("INDEXER_USER", "").strip()
    idx_pass = os.getenv("INDEXER_PASS", "").strip()
    verify_ssl = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"
    index_pattern = os.getenv("INDEXER_INDEX", "wazuh-alerts-*").strip()

    agent_name = os.getenv("WAZUH_AGENT", "").strip()
    min_level = int(os.getenv("WAZUH_MIN_LEVEL", "0"))
    rule_id = os.getenv("WAZUH_RULE_ID", "").strip()
    lookback = int(os.getenv("LOOKBACK_MINUTES", "60"))

    if not all([idx_url, idx_user, idx_pass]):
        raise RuntimeError("Faltan variables Indexer en .env (INDEXER_URL/INDEXER_USER/INDEXER_PASS).")

    now = datetime.now(timezone.utc)
    gte = (now - timedelta(minutes=lookback)).isoformat()

    must_filters: List[Dict[str, Any]] = [{"range": {"timestamp": {"gte": gte}}}]
    if agent_name:
        must_filters.append({"term": {"agent.name": agent_name}})
    if min_level > 0:
        must_filters.append({"range": {"rule.level": {"gte": min_level}}})
    if rule_id:
        must_filters.append({"term": {"rule.id": rule_id}})

    query = {
        "size": 25,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": must_filters}},
    }

    url = f"{idx_url}/{index_pattern}/_search"
    r = requests.get(
        url,
        auth=(idx_user, idx_pass),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json=query,
        verify=verify_ssl,
        timeout=25,
    )

    if r.status_code != 200:
        raise RuntimeError(f"Indexer search error {r.status_code}: {r.text}")

    hits = r.json().get("hits", {}).get("hits", [])
    return hits


def notify_n8n(payload: Dict[str, Any]) -> None:
    """
    Envía un POST al webhook de n8n para disparar notificaciones (email/telegram).
    Si no hay N8N_WEBHOOK_URL configurada, no hace nada.
    """
    url = os.getenv("N8N_WEBHOOK_URL", "").strip()
    if not url:
        return
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[WARN] No se pudo notificar a n8n: {e}")

def main() -> int:
    load_dotenv()

    state = load_state()
    processed = set(state.get("processed_ids", []))

    hits = indexer_search()
    if not hits:
        print("No hay alertas (según filtro). OK.")
        return 0

    created = []
    new_count = 0

    for h in hits:
        alert_id = h.get("_id")
        if not alert_id or alert_id in processed:
            continue

        src = h.get("_source", {})
        agent = (src.get("agent") or {}).get("name", "unknown-agent")
        rule = src.get("rule") or {}
        rid = rule.get("id", "unknown")
        lvl = rule.get("level", "unknown")
        desc = rule.get("description", "Wazuh alert")
        ts = src.get("timestamp", src.get("@timestamp", "unknown-time"))

        srcip = get_src_ip_from_alert_source(src)

        summary = f"[Wazuh] L{lvl} {agent} - {desc}"
        description = "\n".join(
            [
                f"indexer_id: {alert_id}",
                f"timestamp: {ts}",
                f"agent: {agent}",
                f"rule_id: {rid}",
                f"level: {lvl}",
                f"description: {desc}",
                f"src_ip: {srcip}" if srcip else "src_ip: (no disponible)",
            ]
        )

        key = jira_create_issue(summary, description, issuetype=os.getenv("JIRA_ISSUE_TYPE", "Incident"))

        notify_n8n({
            "ticket_key": key,
            "ticket_url": f"https://{os.getenv('JIRA_DOMAIN')}/browse/{key}",
            "agent": agent,
            "rule_id": str(rid),
            "level": int(lvl) if str(lvl).isdigit() else lvl,
            "description": desc,
            "src_ip": srcip or "",
            "timestamp": ts,
        })

        created.append(key)
        processed.add(alert_id)
        new_count += 1

        # Para no spamear Jira en una ejecución
        if new_count >= 5:
            break

    state["processed_ids"] = list(processed)[-500:]
    save_state(state)

    if created:
        print("Tickets creados:", ", ".join(created))
    else:
        print("No había alertas nuevas (deduplicación). OK.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

