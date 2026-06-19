import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idautils


ida_auto.auto_wait()

source_ea = next(
    (
        ea
        for ea in idautils.Functions()
        if "invoke_raw_vtable_slot_2" in ida_funcs.get_func_name(ea)
    ),
    None,
)
output = pathlib.Path(__file__).with_name("check_named_vtable.txt")
if source_ea is None:
    output.write_text("function_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

cfunc = ida_hexrays.decompile(source_ea)
lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
call_line = next((line for line in lines if "object->demo_method_2" in line), None)

index_action = "pseudocode_xrefs:show_vtable_index"
index_registered = index_action in ida_kernwin.get_registered_actions()
index_shortcut = (
    ida_kernwin.get_action_shortcut(index_action) if index_registered else None
)
ok = (
    call_line is not None
    and "g_vtable_addend" in call_line
    and "scale_value" in call_line
    and index_registered
    and index_shortcut == "I"
)
output.write_text(
    f"call_line={call_line!r}\n"
    f"index_registered={index_registered}\n"
    f"index_shortcut={index_shortcut!r}\n"
    f"ok={ok}\n",
    encoding="ascii",
)
ida_pro.qexit(0 if ok else 1)
