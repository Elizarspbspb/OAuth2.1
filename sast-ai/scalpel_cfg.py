import ast
import networkx as nx
from scalpel.cfg import CFGBuilder


def _extract_func_source(source_code: str, target_line: int) -> tuple[str, int, str]:
    """Находит исходный код целевой функции и её начальную строку."""
    tree = ast.parse(source_code)
    lines = source_code.splitlines()

    best_func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= target_line <= node.end_lineno:
                if best_func is None or (node.end_lineno - node.lineno) < (best_func.end_lineno - best_func.lineno):
                    best_func = node

    if not best_func:
        return source_code, 1, "<module>"

    func_lines = lines[best_func.lineno - 1 : best_func.end_lineno]
    return "\n".join(func_lines), best_func.lineno, best_func.name


def build_scalpel_dominators(source_code: str, sink_line: int) -> tuple[set[int], set[int]]:
    """
    Строит граф потоков управления (CFG) с помощью готовой библиотеки Scalpel
    и находит обязательные строки (доминаторы) через NetworkX.
    """
    func_code, start_line, _ = _extract_func_source(source_code, sink_line)

    # 1. Готовый построитель CFG из библиотеки Scalpel
    cfg = CFGBuilder().build_from_src("target_func", func_code)

    nx_graph = nx.DiGraph()
    block_to_lines = {}
    all_func_lines = set()
    sink_block_ids = []

    for block in cfg.get_all_blocks():
        nx_graph.add_node(block.id)
        lines_in_block = set()

        for stmt in block.statements:
            if hasattr(stmt, "lineno"):
                # Переводим относительную строку внутри функции в глобальную строку файла
                real_line = start_line + stmt.lineno - 1
                lines_in_block.add(real_line)
                all_func_lines.add(real_line)
                if real_line == sink_line:
                    sink_block_ids.append(block.id)

        block_to_lines[block.id] = lines_in_block

        for link in block.exits:
            nx_graph.add_edge(block.id, link.target.id)

    if not sink_block_ids:
        return set(), all_func_lines

    # 2. Алгоритм доминаторов из NetworkX (пересечение для всех блоков выхода)
    entry_id = cfg.entryblock.id
    idom = nx.immediate_dominators(nx_graph, entry_id)

    common_dom_blocks = None
    for s_block in sink_block_ids:
        if s_block not in idom:
            continue
        path_blocks = set()
        curr = s_block
        while curr in idom:
            path_blocks.add(curr)
            if curr == entry_id:
                break
            curr = idom[curr]

        if common_dom_blocks is None:
            common_dom_blocks = path_blocks
        else:
            common_dom_blocks &= path_blocks

    if not common_dom_blocks:
        return set(), all_func_lines

    dominator_lines = set()
    for b_id in common_dom_blocks:
        for line in block_to_lines.get(b_id, set()):
            if line < sink_line:
                dominator_lines.add(line)

    return dominator_lines, all_func_lines