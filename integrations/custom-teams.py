#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integração Wazuh -> Microsoft Teams (Webhook) com deep link para o Discover.
- Gera permalink para: https://10.96.123.166/app/data-explorer/discover
- Aplica query KQL (rule.id + agent.name [+ computer]) e janela de tempo ±5min.
"""

import sys
import json
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone

# ===================== CONFIG =====================
# Base do seu Wazuh Dashboard (sem barra no fim)
DASH_BASE = "https://10.96.123.166"
# Rota do Discover (Data Explorer)
DISCOVER_PATH = "/app/data-explorer/discover"
# Index pattern conforme aparece na sua URL
INDEX_PATTERN = "wazuh-alerts-*"
# Janela de tempo em torno do evento
TIME_PAD_BEFORE_MIN = 5
TIME_PAD_AFTER_MIN = 5
# Timeout do POST no Teams (segundos)
HTTP_TIMEOUT = 10
# =================================================

def safe_get(d, *keys, default=""):
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d

def parse_ts(ts: str):
    """
    Aceita formatos comuns:
      - '2025-09-16T12:34:56.789Z'
      - '2025-09-16T12:34:56Z'
      - '2025-09-16T12:34:56.789+0000' / '-0300' (sem ':')
      - ISO 8601 com timezone '+00:00'
    Retorna datetime em UTC ou None.
    """
    if not ts:
        return None
    try:
        s = ts
        if s.endswith('Z'):
            s = s[:-1] + "+00:00"
        # Inserir ':' no fuso se vier +0000/-0300 etc.
        if ('+' in s or '-' in s[10:]) and s[-3:] and s[-3] != ':':
            signpos = max(s.rfind('+'), s.rfind('-'))
            if signpos != -1 and len(s) - signpos >= 5:
                tz = s[signpos:]
                if len(tz) >= 5 and tz[3] != ':':
                    s = s[:signpos] + tz[:3] + ":" + tz[3:]
        dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def rison_quote(value: str) -> str:
    """Escape simples para uso entre aspas simples em rison."""
    return (value or "").replace("'", "\\'")

def build_discover_link(rule_id, agent_name, computer, event_dt_utc):
    """
    Monta link do Discover no formato:
      https://.../app/data-explorer/discover#?_a=...&_g=...&_q=...
    - _a: estado do app (indexPattern, colunas, etc.)
    - _g: tempo e refresh
    - _q: query KQL (Kuery)
    """
    # ------- Query (KQL) -------
    parts = []
    if rule_id:
        parts.append(f"rule.id:{rule_id}")
    if agent_name:
        parts.append(f'agent.name:"{agent_name}"')
    # Em Windows, 'computer' pode ajudar a desambiguar
    if computer and (computer != agent_name):
        parts.append(f'data.win.system.computer:"{computer}"')
    kuery = " AND ".join(parts) if parts else "*"

    # ------- Tempo (_g) -------
    if event_dt_utc:
        start = (event_dt_utc - timedelta(minutes=TIME_PAD_BEFORE_MIN)) \
            .isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = (event_dt_utc + timedelta(minutes=TIME_PAD_AFTER_MIN)) \
            .isoformat(timespec="milliseconds").replace("+00:00", "Z")
        g = f"(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'{rison_quote(start)}',to:'{rison_quote(end)}'))"
    else:
        # Fallback: últimos 10 minutos
        g = "(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-10m,to:now))"

    # ------- Estado do app (_a) -------
    a = f"(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:'{rison_quote(INDEX_PATTERN)}',view:discover))"

    # ------- Query container (_q) -------
    q = f"(filters:!(),query:(language:kuery,query:'{rison_quote(kuery)}'))"

    # Codificar preservando sintaxe rison
    safe_chars = "()':,!*"
    base = DASH_BASE.rstrip('/') + DISCOVER_PATH + "#?"
    return (
        base +
        "_a=" + urllib.parse.quote(a, safe=safe_chars) + "&" +
        "_g=" + urllib.parse.quote(g, safe=safe_chars) + "&" +
        "_q=" + urllib.parse.quote(q, safe=safe_chars)
    )

def main():
    # Parâmetros que o Integrator envia:
    # 1) caminho do arquivo com o alerta, 2) api_key (se houver), 3) hook_url
    if len(sys.argv) < 2:
        print("Uso: custom-teams <alert.json> [api_key] [webhook_url]", file=sys.stderr)
        sys.exit(2)

    alert_path = sys.argv[1]
    api_key_arg = sys.argv[2] if len(sys.argv) > 2 else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    with open(alert_path, "r", encoding="utf-8") as f:
        alert = json.load(f)

    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    win = alert.get("win", {}) or {}
    ed = win.get("eventdata", {}) or {}

    level = rule.get("level", 0) or 0
    rule_id = rule.get("id")
    desc = rule.get("description", "Alerta do Wazuh")
    groups = ", ".join(rule.get("groups", []))
    mitre = ", ".join(rule.get("mitre", {}).get("id", []))

    # timestamp do documento
    ts = alert.get("@timestamp") or alert.get("timestamp") or ""
    event_dt_utc = parse_ts(ts)

    computer = safe_get(alert, "data", "win", "system", "computer", default=agent.get("name", ""))
    image = ed.get("Image") or ed.get("image", "")
    cmd = ed.get("CommandLine") or ed.get("commandLine", "")
    target = ed.get("TargetFilename") or ed.get("targetFilename", "")
    parent = ed.get("ParentImage") or ed.get("parentImage", "")

    # Cor por severidade (Teams requer hex sem '#')
    color = "E81123" if level >= 12 else ("FF8C00" if level >= 10 else "0078D4")

    # Link Discover
    discover_url = build_discover_link(rule_id, agent.get("name", ""), computer, event_dt_utc)

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Wazuh Alert",
        "themeColor": color,
        "title": f"Wazuh: Regra {rule_id} (Nível {level})",
        "sections": [{
            "activityTitle": desc,
            "facts": [
                {"name": "Agente", "value": f"{agent.get('name','')} ({agent.get('id','')})"},
                {"name": "Host", "value": computer or "-"},
                {"name": "Grupos", "value": groups or "-"},
                {"name": "MITRE", "value": mitre or "-"},
                {"name": "Imagem", "value": image or "-"},
                {"name": "Comando", "value": cmd or "-"},
                {"name": "Alvo", "value": target or "-"},
                {"name": "Parent", "value": parent or "-"},
                {"name": "Tempo", "value": ts or "-"}
            ],
            "markdown": True
        }],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "🔎 Abrir no Wazuh",
                "targets": [{"os": "default", "uri": discover_url}]
            }
        ]
    }

    r = requests.post(hook_url, json=payload, timeout=HTTP_TIMEOUT)
    r.raise_for_status()  # se falhar, o Integrator registra no ossec.log

if __name__ == "__main__":
    main()
