import json
import os
import requests
import jedi
from jedi_slicer import get_jedi_context_slice
from bytecode import build_bytecode_dominators

from scalpel_cfg import build_scalpel_dominators

# =====================================================================
# НАСТРОЙКИ
# =====================================================================
SEMGREP_REPORT_PATH = "../artifacts/semgrep-auto-vuln-app.json"   # Путь к твоему JSON-отчету Semgrep
#PROJECT_ROOT_DIR = "../auth_server/"                       # Папка проекта, откуда запускался Semgrep
PROJECT_ROOT_DIR = "../"                       # Папка проекта, откуда запускался Semgrep
OLLAMA_MODEL_NAME = "qwen2.5-coder:7b"        # Впиши сюда свою модель из ollama list
OLLAMA_URL = "http://localhost:11434/api/generate"
# =====================================================================


def ask_llm_with_jedi_context(jedi_context: str, sink_line: int, rule_message: str) -> dict:
    """Отправляет полный межпроцедурный срез от Jedi в локальную LLM."""
    prompt = f"""Ты — эксперт по безопасности приложений (AppSec).
Статический анализатор Semgrep сработал на строку {sink_line} с сообщением:
"{rule_message}"

Ниже представлен межпроцедурный срез кода (включая внешние константы, импортированные определения и целевую функцию целиком):
{jedi_context}

Задача:
Проанализируй полный контекст (откуда приходят данные, как задаются константы/секреты и есть ли защита до строки {sink_line}).
Определи, является ли это реальной уязвимостью (is_vulnerable: true) или ложным срабатыванием (is_vulnerable: false).

Верни ответ СТРОГО в формате JSON:
{{
  "is_vulnerable": true или false,
  "sanitizer_line": число (номер строки с защитой, если is_vulnerable=false) или null,
  "reasoning": "краткое и точное объяснение на русском со ссылками на строки кода"
}}"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL_NAME,
                "prompt": prompt,
                "format": "json",
                "stream": False,
                "options": {"temperature": 0.0, "num_ctx": 4096}
            },
            timeout=3600
        )
        response.raise_for_status()
        return json.loads(response.json()["response"])
    except Exception as e:
        return {"is_vulnerable": True, "reasoning": f"Ошибка обращения к LLM: {e}"}


def run_jedi_pipeline():
    if not os.path.exists(SEMGREP_REPORT_PATH):
        raise FileNotFoundError(f"Файл отчета не найден: {os.path.abspath(SEMGREP_REPORT_PATH)}")

    with open(SEMGREP_REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    print(f"Всего срабатываний в отчете Semgrep: {len(results)}\n" + "=" * 75)

    for idx, res in enumerate(results):
        raw_path = res["path"]
        full_path = raw_path if os.path.exists(raw_path) else os.path.join(PROJECT_ROOT_DIR, raw_path)
        sink_line = res["start"]["line"]
        message = res["extra"]["message"]

        print(f"\n[result #{idx}] Файл: {full_path} | Строка срабатывания: {sink_line}")
        print(f"Правило: {res['check_id']}")

        if not full_path.endswith(".py"):
            print("-> Пропуск: файл не является Python-скриптом (.py)")
            continue

        if not os.path.exists(full_path):
            print(f"-> Пропуск: файл не найден по пути {full_path}")
            continue

        try:
            # 1. Получаем полный межпроцедурный срез через Jedi
            jedi_slice = get_jedi_context_slice(
                project_dir=PROJECT_ROOT_DIR,
                file_path=full_path,
                target_line=sink_line
            )

            print("\n--- ПОЛНЫЙ КОНТЕКСТ ИЗ JEDI (ОТПРАВЛЯЕМ В МОДЕЛЬ) ---")
            print(jedi_slice)
            print("------------------------------------------------------")

            # 2. Отправляем в локальную модель Ollama
            print(f"\nЖдем ответ от модели ({OLLAMA_MODEL_NAME})...")
            answer = ask_llm_with_jedi_context(jedi_slice, sink_line, message)

            # 3. Выводим результат
            is_vuln = answer.get("is_vulnerable", True)
            verdict_text = "ПРАВДА (Реальная уязвимость / TP)" if is_vuln else "ЛОЖЬ (Ложная тревога / FP)"

            print(f"\nИтог модели: {verdict_text}")
            print(f"Объяснение: {answer.get('reasoning')}")

            print(f"\n-----------------------------------------------------")
            # --- ПРОВЕРКА ЧЕРЕЗ НАШ ГРАФ БАЙТ-КОДА ---
            with open(full_path, "r", encoding="utf-8") as f:
                src_code = f.read()
            ctx = jedi.Script(code=src_code, path=full_path).get_context(line=sink_line)
            func_name = ctx.name if (ctx and ctx.type == "function") else "<module>"

            dom_lines, _ = build_bytecode_dominators(src_code, func_name, sink_line)
            #dom_lines, _ = build_scalpel_dominators(src_code, sink_line)
            print(f"Обязательные строки (доминаторы байт-кода): {sorted(list(dom_lines))}")
            for idx_line, line_text in enumerate(src_code.splitlines(), start=1):
                if idx_line in dom_lines:
                    print(f"{idx_line:4d} | {line_text}")
            print("-----------------------------------------------------\n")

            # 2. Корректно проверяем ответ модели
            raw_vuln = answer.get("is_vulnerable", True)
            is_vuln = raw_vuln if isinstance(raw_vuln, bool) else str(raw_vuln).strip().lower() == "true"
            if is_vuln:
                print("ВЕРИФИКАТОР: ПРАВДА ПОДТВЕРЖДЕНА (Модель нашла уязвимость, оставляем в отчете).")
            else:
                san_line = answer.get("sanitizer_line")
                if isinstance(san_line, int) and san_line in dom_lines:
                    print(f"ВЕРИФИКАТОР: ЛОЖЬ ПОДТВЕРЖДЕНА (Строка защиты {san_line} гарантирована на всех путях).")
                else:
                    print(f"ВЕРИФИКАТОР: ВРАНЬЕ МОДЕЛИ ЗАБЛОКИРОВАНО! Строка {san_line} обходится -> ОСТАВЛЯЕМ КАК БАГ!")
            
            #if not is_vuln:  # Если модель сказала "бага нет" — проверяем её по графу!
            #    san_line = answer.get("sanitizer_line")
            #    if isinstance(san_line, int) and san_line in dom_lines:
            #        print(f"ВЕРИФИКАТОР: ЛОЖЬ ПОДТВЕРЖДЕНА (строка {san_line} гарантирована на всех путях)")
            #    else:
            #        print(f"ВЕРИФИКАТОР: ВРАНЬЕ МОДЕЛИ ЗАБЛОКИРОВАНО! Строка {san_line} обходится или не существует -> ОСТАВЛЯЕМ КАК БАГ!")
        
        except Exception as e:
            print(f"-> Ошибка при обработке: {e}")

        print("=" * 75)


if __name__ == "__main__":
    run_jedi_pipeline()