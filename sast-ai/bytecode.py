import dis
import networkx as nx


def _find_code_object(code_obj, target_name: str):
    for const in code_obj.co_consts:
        if hasattr(const, "co_name"):
            if const.co_name == target_name:
                return const
            nested = _find_code_object(const, target_name)
            if nested is not None:
                return nested
    return None


def build_bytecode_dominators(source_code: str, target_func_name: str, sink_line: int) -> tuple[set[int], set[int]]:
    module_code = compile(source_code, filename="<target>", mode="exec")
    func_code_obj = module_code if target_func_name == "<module>" else _find_code_object(module_code, target_func_name)

    if func_code_obj is None:
        raise ValueError(f"Байт-код функции '{target_func_name}' не найден.")

    instructions = list(dis.get_instructions(func_code_obj))

    cfg = nx.DiGraph()
    offset_to_line = {}
    all_func_lines = set()
    sink_offsets = []

    for idx, instr in enumerate(instructions):
        curr_offset = instr.offset
        lineno = instr.positions.lineno if hasattr(instr, "positions") and instr.positions else instr.starts_line

        cfg.add_node(curr_offset)
        if lineno is not None:
            offset_to_line[curr_offset] = lineno
            all_func_lines.add(lineno)
            if lineno == sink_line:
                sink_offsets.append(curr_offset)

        opname = instr.opname
        is_jump = "JUMP" in opname and isinstance(instr.argval, int)

        if opname in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"):
            pass
        elif is_jump and ("IF" not in opname and "NONE" not in opname):
            cfg.add_edge(curr_offset, instr.argval)
        elif is_jump:
            cfg.add_edge(curr_offset, instr.argval)
            if idx + 1 < len(instructions):
                cfg.add_edge(curr_offset, instructions[idx + 1].offset)
        else:
            if idx + 1 < len(instructions):
                cfg.add_edge(curr_offset, instructions[idx + 1].offset)

    if not sink_offsets or not instructions:
        return set(), all_func_lines

    entry_offset = instructions[0].offset
    idom = nx.immediate_dominators(cfg, entry_offset)

    common_dominator_offsets = None
    for s_offset in sink_offsets:
        if s_offset not in idom:
            continue
        path_doms = set()
        curr = s_offset
        while curr in idom:
            path_doms.add(curr)
            if curr == entry_offset:
                break
            curr = idom[curr]

        if common_dominator_offsets is None:
            common_dominator_offsets = path_doms
        else:
            common_dominator_offsets &= path_doms

    if not common_dominator_offsets:
        return set(), all_func_lines

    dominator_lines = set()
    for off in common_dominator_offsets:
        line = offset_to_line.get(off)
        if line is not None and line < sink_line:
            dominator_lines.add(line)

    return dominator_lines, all_func_lines