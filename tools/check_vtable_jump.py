import pathlib

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_name
import ida_pro
import idautils


ida_auto.auto_wait()

target_ea = None
for ea in idautils.Functions():
    if "invoke_raw_vtable_slot_2" in ida_funcs.get_func_name(ea):
        target_ea = ea
        break

output = pathlib.Path(__file__).with_name("check_vtable_jump.txt")
if target_ea is None:
    output.write_text("function_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

cfunc = ida_hexrays.decompile(target_ea)
object_lvar = next((lvar for lvar in cfunc.lvars if lvar.name == "object"), None)
type_text = str(object_lvar.type()) if object_lvar is not None else ""
vtable_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "VftJumpType_vft")
entry_ea = vtable_ea + 2 * (8 if ida_ida.inf_is_64bit() else 4)
method_ea = (
    ida_bytes.get_qword(entry_ea)
    if ida_ida.inf_is_64bit()
    else ida_bytes.get_dword(entry_ea)
)
method_name = ida_funcs.get_func_name(method_ea)

ok = (
    object_lvar is not None
    and "VftJumpType" in type_text
    and vtable_ea != ida_idaapi.BADADDR
    and "demo_method_2" in method_name
)

output.write_text(
    f"object_type={type_text!r}\n"
    f"vtable_ea=0x{vtable_ea:X}\n"
    f"entry_ea=0x{entry_ea:X}\n"
    f"method_ea=0x{method_ea:X}\n"
    f"method_name={method_name!r}\n"
    f"ok={ok}\n",
    encoding="ascii",
)

ida_pro.qexit(0 if ok else 1)
