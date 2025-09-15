#!/usr/bin/env python3
import sys, json, requests

def safe_get(d, *keys, default=""):
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d

def main():
    # Parâmetros que o Integrator envia:
    # 1) caminho do arquivo com o alerta, 2) api_key (se houver), 3) hook_url
    alert_path = sys.argv[1]
    api_key_arg = sys.argv[2] if len(sys.argv) > 2 else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    with open(alert_path, "r", encoding="utf-8") as f:
        alert = json.load(f)

    rule     = alert.get("rule", {})
    agent    = alert.get("agent", {})
    win      = alert.get("win", {})
    ed       = win.get("eventdata", {})

    level    = rule.get("level")
    rule_id  = rule.get("id")
    desc     = rule.get("description", "Alerta do Wazuh")
    groups   = ", ".join(rule.get("groups", []))
    mitre    = ", ".join(rule.get("mitre", {}).get("id", []))

    computer = safe_get(alert, "data", "win", "system", "computer", default=agent.get("name",""))
    image    = ed.get("Image") or ed.get("image","")
    cmd      = ed.get("CommandLine") or ed.get("commandLine","")
    target   = ed.get("TargetFilename") or ed.get("targetFilename","")
    parent   = ed.get("ParentImage") or ed.get("parentImage","")

    # cor por severidade (Teams usa hex sem '#')
    color = "E81123" if level >= 12 else ("FF8C00" if level >= 10 else "0078D4")

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
          {"name": "Host", "value": computer},
          {"name": "Grupos", "value": groups},
          {"name": "MITRE", "value": mitre or "-"},
          {"name": "Imagem", "value": image or "-"},
          {"name": "Comando", "value": cmd or "-"},
          {"name": "Alvo", "value": target or "-"},
          {"name": "Parent", "value": parent or "-"}
        ],
        "markdown": True
      }]
    }

    r = requests.post(hook_url, json=payload, timeout=10)
    r.raise_for_status()  # Se falhar, o Integrator registra no ossec.log

if __name__ == "__main__":
    main()
