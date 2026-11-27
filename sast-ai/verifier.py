def formal_verify_hypothesis(
    llm_output: dict,
    dominator_lines: set[int],
    all_func_lines: set[int]
) -> dict:
    """
    Проверяет гипотезу LLM на соответствие графу байт-кода.
    При малейшем нарушении срабатывает Fail-Safe (возврат в True Positive).
    """
    is_fp = llm_output.get("is_false_positive", False)
    claimed_line = llm_output.get("sanitizer_line")

    if not is_fp:
        return {
            "final_status": "CONFIRMED_TP",
            "math_proof": "Уязвимость подтверждена моделью (гипотеза FP не выдвигалась).",
            "llm_reasoning": llm_output.get("reasoning")
        }

    # Проверка 1: Существование инструкции на этой строке в байт-коде целевой функции
    if not isinstance(claimed_line, int) or claimed_line not in all_func_lines:
        return {
            "final_status": "HALLUCINATION_BLOCKED (Fallback -> TP)",
            "math_proof": f"Строка {claimed_line} отсутствует в байт-коде целевой функции.",
            "llm_reasoning": llm_output.get("reasoning")
        }

    # Проверка 2: Строгое доминирование в графе переходов байт-кода
    if claimed_line not in dominator_lines:
        return {
            "final_status": "BYPASS_DETECTED (Fallback -> TP)",
            "math_proof": (
                f"Строка {claimed_line} не доминирует над точкой уязвимости в графе байт-кода "
                f"(обязательные строки: {sorted(list(dominator_lines))}). Возможен обход по ветке перехода."
            ),
            "llm_reasoning": llm_output.get("reasoning")
        }

    return {
        "final_status": "VERIFIED_FP",
        "math_proof": f"Доказано по графу байт-кода: строка {claimed_line} выполняется на 100% путей до уязвимости.",
        "llm_reasoning": llm_output.get("reasoning")
    }