import os
import json
import argparse
from typing import Dict, Any, List

import requests
from dotenv import load_dotenv


def adf_from_text(text: str) -> Dict[str, Any]:
    """
    Convierte texto plano a Atlassian Document Format (ADF) para Jira Cloud API v3.
    Cada línea -> un párrafo.
    """
    lines = [ln.strip() for ln in (text or "").splitlines()]
    lines = [ln for ln in lines if ln] or ["(sin descripción)"]

    content: List[Dict[str, Any]] = []
    for ln in lines:
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": ln}],
            }
        )

    return {"type": "doc", "version": 1, "content": content}


def jira_request(method: str, url: str, auth: tuple, json_body: Dict[str, Any] | None = None) -> requests.Response:
    headers = {"Accept": "application/json"}
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    resp = requests.request(
        method=method,
        url=url,
        auth=auth,
        headers=headers,
        json=json_body,
        timeout=20,
    )
    return resp


def main() -> int:
    load_dotenv()

    jira_domain = os.getenv("JIRA_DOMAIN", "").strip()
    project_key = os.getenv("JIRA_PROJECT_KEY", "").strip()
    jira_email = os.getenv("JIRA_EMAIL", "").strip()
    jira_token = os.getenv("JIRA_TOKEN", "").strip()
    issue_type_default = os.getenv("JIRA_ISSUE_TYPE", "Incident").strip()

    parser = argparse.ArgumentParser(description="SOAR - Crear ticket en Jira (Cloud API v3)")
    parser.add_argument("--summary", required=True, help="Título del ticket (summary)")
    parser.add_argument("--description", default="", help="Descripción en texto plano (se convierte a ADF)")
    parser.add_argument("--issue-type", default=issue_type_default, help="Tipo de issue (ej: Incident, Task)")
    parser.add_argument("--project-key", default=project_key, help="Project key (ej: KAN)")
    parser.add_argument("--check-auth", action="store_true", help="Comprueba /myself antes de crear el ticket")

    args = parser.parse_args()

    # Validaciones mínimas
    if not jira_domain or not jira_email or not jira_token:
        print("ERROR: Falta configurar JIRA_DOMAIN / JIRA_EMAIL / JIRA_TOKEN en .env")
        return 2

    if not args.project_key:
        print("ERROR: Falta JIRA_PROJECT_KEY (ponlo en .env o pásalo con --project-key)")
        return 2

    base = f"https://{jira_domain}"
    auth = (jira_email, jira_token)

    # (Opcional) comprobar auth
    if args.check_auth:
        me_url = f"{base}/rest/api/3/myself"
        r = jira_request("GET", me_url, auth)
        if r.status_code != 200:
            print(f"AUTH FAIL: {r.status_code} {r.text}")
            return 3
        me = r.json()
        print(f"AUTH OK: {me.get('displayName')} <{me.get('emailAddress')}>")

    # Crear issue
    issue_url = f"{base}/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": args.project_key},
            "summary": args.summary,
            "description": adf_from_text(args.description),
            "issuetype": {"name": args.issue_type},
        }
    }

    r = jira_request("POST", issue_url, auth, json_body=payload)

    if r.status_code not in (200, 201):
        # Errores típicos:
        # 401 -> token/email mal
        # 403 -> permisos "Create issues"
        # 400 -> issuetype incorrecto, campos mal
        print(f"ERROR creando issue: {r.status_code}")
        print(r.text)
        return 4

    data = r.json()
    key = data.get("key")
    issue_id = data.get("id")
    print("OK ✅ Ticket creado")
    print(f"- key: {key}")
    print(f"- id:  {issue_id}")
    print(f"- browse: {base}/browse/{key}" if key else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
