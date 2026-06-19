import pathlib

import ida_auto
import ida_kernwin
import ida_pro


ida_auto.auto_wait()

action_name = "pseudocode_xrefs:show"
registered = action_name in ida_kernwin.get_registered_actions()
shortcut = ida_kernwin.get_action_shortcut(action_name) if registered else None
label = ida_kernwin.get_action_label(action_name) if registered else None
vtable_action_name = "pseudocode_xrefs:jump_vtable_target"
vtable_registered = vtable_action_name in ida_kernwin.get_registered_actions()
vtable_shortcut = (
    ida_kernwin.get_action_shortcut(vtable_action_name)
    if vtable_registered
    else None
)
index_action_name = "pseudocode_xrefs:show_vtable_index"
index_registered = index_action_name in ida_kernwin.get_registered_actions()
index_shortcut = (
    ida_kernwin.get_action_shortcut(index_action_name)
    if index_registered
    else None
)
n_actions = [
    name
    for name in ida_kernwin.get_registered_actions()
    if ida_kernwin.get_action_shortcut(name) in ("N", "n")
]

output = pathlib.Path(__file__).with_name("check_plugin.txt")
output.write_text(
    f"registered={registered}\n"
    f"shortcut={shortcut!r}\n"
    f"label={label!r}\n"
    f"vtable_registered={vtable_registered}\n"
    f"vtable_shortcut={vtable_shortcut!r}\n"
    f"index_registered={index_registered}\n"
    f"index_shortcut={index_shortcut!r}\n"
    f"n_actions={n_actions!r}\n",
    encoding="ascii",
)

ida_pro.qexit(
    0
    if registered
    and shortcut == "K"
    and vtable_registered
    and vtable_shortcut == "J"
    and index_registered
    and index_shortcut == "I"
    else 1
)
