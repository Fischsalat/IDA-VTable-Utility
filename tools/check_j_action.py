import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idautils


ida_auto.auto_wait()

source_ea = None
expected_ea = None
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    if "invoke_raw_vtable_slot_2" in name:
        source_ea = ea
    elif "demo_method_2" in name:
        expected_ea = ea

output = pathlib.Path(__file__).with_name("check_j_action.txt")
if source_ea is None or expected_ea is None:
    output.write_text("required_functions_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

vu = ida_hexrays.open_pseudocode(source_ea, 0)
lines = [ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()]
line_index = next(
    (index for index, line in enumerate(lines) if "VTABLE[0x2]" in line),
    None,
)
if line_index is None:
    output.write_text("vtable_token_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

column = lines[line_index].index("VTABLE[0x2]") + 2
place, _, _ = ida_kernwin.get_custom_viewer_place(vu.ct, False)
ida_kernwin.place_t.as_simpleline_place_t(place).n = line_index
moved = ida_kernwin.jumpto(vu.ct, place, column, 0)
ida_kernwin.activate_widget(vu.ct, True)
activated = ida_kernwin.process_ui_action("pseudocode_xrefs:jump_vtable_target")
screen_ea = ida_kernwin.get_screen_ea()
ok = moved and activated and screen_ea == expected_ea

output.write_text(
    f"line_index={line_index}\n"
    f"column={column}\n"
    f"moved={moved}\n"
    f"activated={activated}\n"
    f"screen_ea=0x{screen_ea:X}\n"
    f"expected_ea=0x{expected_ea:X}\n"
    f"ok={ok}\n",
    encoding="ascii",
)

ida_pro.qexit(0 if ok else 1)
