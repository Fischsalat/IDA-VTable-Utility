import pathlib
import ida_auto
import ida_netnode
import ida_pro

ida_auto.auto_wait()
value = ida_netnode.netnode("$ pseudocode_xrefs declarations").supstr_ea(0x140023130)
ok = value == "AActor"
pathlib.Path(__file__).with_name("check_declaration_persistence.txt").write_text(
    f"value={value!r}\nok={ok}\n", encoding="utf-8")
ida_pro.qexit(0 if ok else 1)
