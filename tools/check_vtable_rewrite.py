import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import ida_pro
import idautils


ida_auto.auto_wait()

target_ea = None
for ea in idautils.Functions():
    if "invoke_raw_vtable_slot_2" in ida_funcs.get_func_name(ea):
        target_ea = ea
        break

output = pathlib.Path(__file__).with_name("check_vtable_rewrite.txt")
if target_ea is None:
    output.write_text("function_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

cfunc = ida_hexrays.decompile(target_ea)
raw_lines = [line.line for line in cfunc.get_pseudocode()]
plain_lines = [ida_lines.tag_remove(line) for line in raw_lines]

expected_plain = "object->VTABLE[0x2](object, 0)"
matching_index = next(
    (index for index, line in enumerate(plain_lines) if expected_plain in line),
    None,
)

colored_object = "\x01\x18object\x02\x18"
colored_vtable = "\x01\x01VTABLE\x02\x01"
colored_number = "\x01\x0c0x2\x02\x0c"
colors_ok = (
    matching_index is not None
    and colored_object in raw_lines[matching_index]
    and colored_vtable in raw_lines[matching_index]
    and colored_number in raw_lines[matching_index]
)

output.write_text(
    f"target=0x{target_ea:X}\n"
    f"matching_index={matching_index!r}\n"
    f"colors_ok={colors_ok}\n"
    + (
        f"raw={raw_lines[matching_index].encode('unicode_escape')!r}\n"
        if matching_index is not None
        else ""
    )
    + "\n".join(plain_lines)
    + "\n",
    encoding="ascii",
)

ida_pro.qexit(0 if matching_index is not None and colors_ok else 1)
