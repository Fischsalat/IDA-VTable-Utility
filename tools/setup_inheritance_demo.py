import pathlib

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_pro
import ida_typeinf
import idautils
import idc


ida_auto.auto_wait()

output = pathlib.Path(__file__).with_name("setup_inheritance_demo.txt")


def function_ea(name):
    return next(
        (ea for ea in idautils.Functions() if ida_funcs.get_func_name(ea) == name),
        None,
    )


source_ea = function_ea("invoke_raw_vtable_slot_2")
targets = {
    "UObject": function_ea("demo_method_0"),
    "AActor": function_ea("demo_method_1"),
    "ASomeActor": function_ea("demo_method_2"),
    "USomeNetClass": function_ea("scale_value"),
}
if source_ea is None or any(ea is None for ea in targets.values()):
    output.write_text("required_functions_not_found\n", encoding="ascii")
    ida_pro.qexit(1)


def replace_udt(name, base_name=None):
    existing = ida_typeinf.tinfo_t()
    if existing.get_named_type(None, name):
        ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)

    udt = ida_typeinf.udt_type_data_t()
    udt.name = name
    if base_name is None:
        void_pointer = ida_typeinf.tinfo_t()
        if not void_pointer.parse("void *value;"):
            raise RuntimeError("failed to parse void pointer")
        udt.add_member("VTable", void_pointer, 0)
    else:
        base_type = ida_typeinf.tinfo_t()
        if not base_type.get_named_type(None, base_name):
            raise RuntimeError(f"base type not found: {base_name}")
        base_member = udt.add_member("base", base_type, 0)
        base_member.set_baseclass()

    result = ida_typeinf.tinfo_t()
    if not result.create_udt(udt):
        raise RuntimeError(f"failed to create UDT: {name}")
    error = result.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    if error != ida_typeinf.TERR_OK:
        raise RuntimeError(
            f"failed to store UDT {name}: {ida_typeinf.tinfo_errstr(error)}"
        )


replace_udt("UObject")
replace_udt("AActor", "UObject")
replace_udt("ASomeActor", "AActor")
replace_udt("USomeNetClass", "UObject")

vtable_addresses = {
    "UObject": 0x140023100,
    "AActor": 0x140023120,
    "ASomeActor": 0x140023140,
    "USomeNetClass": 0x140023160,
}
pointer_size = 8
for class_name, vtable_ea in vtable_addresses.items():
    for slot in range(3):
        entry_ea = vtable_ea + slot * pointer_size
        ida_bytes.patch_qword(entry_ea, targets[class_name])
        ida_bytes.create_qword(entry_ea, pointer_size)
    ida_name.set_name(vtable_ea, f"{class_name}_Vft", ida_name.SN_FORCE)
    idc.SetType(vtable_ea, f"void *{class_name}_Vft[3];")

if not idc.SetType(
    source_ea,
    "int __fastcall invoke_raw_vtable_slot_2(AActor *object);",
):
    raise RuntimeError("failed to type hierarchy demo function")

ida_hexrays.mark_cfunc_dirty(source_ea, False)
cfunc = ida_hexrays.decompile(source_ea)
lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
call_line = next((line for line in lines if "object->demo_method_1" in line), None)

type_checks = []
for derived_name, expected_base in (
    ("AActor", "UObject"),
    ("ASomeActor", "AActor"),
    ("USomeNetClass", "UObject"),
):
    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    found_base = None
    if tif.get_named_type(None, derived_name) and tif.get_udt_details(udt):
        found_base = next(
            (
                str(member.type)
                for member in udt
                if member.is_baseclass()
            ),
            None,
        )
    type_checks.append((derived_name, expected_base, found_base))

ok = call_line is not None and all(
    expected_base in (found_base or "")
    for _, expected_base, found_base in type_checks
)
output.write_text(
    f"call_line={call_line!r}\n"
    f"pseudocode={lines!r}\n"
    f"type_checks={type_checks!r}\n"
    f"targets={targets!r}\n"
    f"ok={ok}\n",
    encoding="ascii",
)
ida_pro.qexit(0 if ok else 1)
