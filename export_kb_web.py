"""Gera kb_web.json para o chatbot estático. Execute após alterar ciberseguranca_kb.py."""

import json

from ciberseguranca_kb import build_web_kb_dict

if __name__ == "__main__":
    path = "kb_web.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_web_kb_dict(), f, ensure_ascii=False, indent=2)
    print(f"Escrito {path}")
