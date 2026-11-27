import os
import re
import jedi


def get_full_definition_lines(def_obj, file_lines: list[str]) -> tuple[int, int]:
    try:
        tree_def = def_obj._name.tree_name.get_definition()
        if tree_def is not None:
            start_line, _ = tree_def.start_pos
            end_line, _ = tree_def.end_pos
            return start_line, min(end_line, len(file_lines))
    except Exception:
        pass
    return def_obj.line, def_obj.line


def get_jedi_context_slice(project_dir: str, file_path: str, target_line: int) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()
    lines = source_code.splitlines()

    project = jedi.Project(path=project_dir)
    script = jedi.Script(code=source_code, path=file_path, project=project)

    # Сначала определяем границы самой целевой функции, чтобы не дублировать внутренние переменные
    context_func = script.get_context(line=target_line)
    func_start, func_end = (None, None)
    if context_func and context_func.type == "function":
        func_start, func_end = get_full_definition_lines(context_func, lines)

    collected_blocks = []
    seen_locations = set()

    # 1. Ищем внешние определения для всех слов на целевой строке
    target_code_line = lines[target_line - 1]
    for match in re.finditer(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", target_code_line):
        col = match.start()
        definitions = script.goto(line=target_line, column=col, follow_imports=True)

        for d in definitions:
            if not d.module_path or "site-packages" in str(d.module_path) or "lib/python" in str(d.module_path):
                continue
            if d.line is None:
                continue

            # Если переменная (например, payload) уже находится ВНУТРИ целевой функции —
            # пропускаем её здесь, так как она всё равно целиком выведется в блоке функции ниже!
            if (
                os.path.abspath(d.module_path) == os.path.abspath(file_path)
                and func_start is not None
                and func_start <= d.line <= func_end
            ):
                continue

            loc_key = (str(d.module_path), d.line)
            if loc_key in seen_locations:
                continue
            seen_locations.add(loc_key)

            with open(d.module_path, "r", encoding="utf-8") as df:
                def_lines = df.read().splitlines()

            start_l, end_l = get_full_definition_lines(d, def_lines)
            snippet = "\n".join(
                f"{l_num:4d} | {def_lines[l_num - 1]}"
                for l_num in range(start_l, end_l + 1)
            )
            rel_file = os.path.relpath(d.module_path, project_dir)
            collected_blocks.append(f"# Внешнее определение {d.name} ({rel_file}):\n{snippet}")

    # 2. Выводим всю целевую функцию целиком (от def до последнего return)
    if func_start is not None:
        func_snippet = "\n".join(
            f"{l_num:4d} | {lines[l_num - 1]}"
            for l_num in range(func_start, func_end + 1)
        )
        collected_blocks.append(f"# Целевая функция {context_func.name}:\n{func_snippet}")
    else:
        collected_blocks.append(f"# Целевая строка:\n{target_line:4d} | {target_code_line}")

    return "\n\n".join(collected_blocks)


if __name__ == "__main__":
    result = get_jedi_context_slice(
        project_dir="../auth_server",
        file_path="../auth_server/my_auth_server.py",
        target_line=192
    )
    print(result)