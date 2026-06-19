import pathlib
import re

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_pro
import idc


ida_auto.auto_wait()

tools_dir = pathlib.Path(__file__).resolve().parent
project_dir = tools_dir.parent
map_path = project_dir / "demo" / "pseudocode_xrefs_demo.map"
output = tools_dir / "setup_complex_demo.txt"

map_lines = map_path.read_text(encoding="utf-8", errors="replace").splitlines()


def symbol_address(fragment):
    for line in map_lines:
        if fragment in line and "$unwind$" not in line:
            matches = re.findall(r"\b[0-9A-Fa-f]{16}\b", line)
            if matches:
                return int(matches[-1], 16)
    raise RuntimeError(f"symbol not found in linker map: {fragment}")


symbols = {
    "demo_method_0": symbol_address("?demo_method_0@"),
    "demo_method_1": symbol_address("?demo_method_1@"),
    "demo_method_2": symbol_address("?demo_method_2@"),
    "invoke_raw_vtable_slot_2": symbol_address("?invoke_raw_vtable_slot_2@"),
    "invoke_vtable_slot_2": symbol_address("?invoke_vtable_slot_2@"),
    "scale_value": symbol_address("?scale_value@"),
    "g_vtable_addend": symbol_address("?g_vtable_addend@"),
    "VftJumpType_vft": symbol_address("VftJumpType_vft"),
}

for name, ea in symbols.items():
    if name.startswith("demo_method_") or name.startswith("invoke_") or name == "scale_value":
        ida_funcs.add_func(ea)
    if not ida_name.set_name(ea, name, ida_name.SN_FORCE):
        raise RuntimeError(f"failed to name 0x{ea:X} as {name}")

declarations = """
struct VftJumpType { void **vtable; };
typedef int (__fastcall *value_transform_t)(int value);
"""
if idc.parse_decls(declarations, idc.PT_SIL) != 0:
    raise RuntimeError("failed to declare complex demo types")

method_type = (
    "int __fastcall demo_method(VftJumpType *self, volatile int *addend, "
    "value_transform_t transform);"
)
type_edits = {
    "demo_method_0": method_type,
    "demo_method_1": method_type,
    "demo_method_2": method_type,
    "invoke_raw_vtable_slot_2": (
        "int __fastcall invoke_raw_vtable_slot_2(VftJumpType *object);"
    ),
    "invoke_vtable_slot_2": (
        "int __fastcall invoke_vtable_slot_2(VftJumpType *object);"
    ),
    "scale_value": "int __fastcall scale_value(int value);",
    "g_vtable_addend": "volatile int g_vtable_addend;",
    "VftJumpType_vft": "void *VftJumpType_vft[3];",
}
for name, declaration in type_edits.items():
    if not idc.SetType(symbols[name], declaration):
        raise RuntimeError(f"failed to apply type to {name}: {declaration}")

cfunc = ida_hexrays.decompile(symbols["invoke_raw_vtable_slot_2"])
plain_lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
call_line = next(
    (line for line in plain_lines if "demo_method_2" in line),
    None,
)
expected_parts = ["object->demo_method_2", "g_vtable_addend", "scale_value"]
ok = call_line is not None and all(part in call_line for part in expected_parts)

output.write_text(
    "\n".join(f"{name}=0x{ea:X}" for name, ea in symbols.items())
    + f"\ncall_line={call_line!r}\n"
    + f"ok={ok}\n",
    encoding="ascii",
)
ida_pro.qexit(0 if ok else 1)
