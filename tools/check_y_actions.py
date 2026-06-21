import pathlib
import ida_auto
import ida_kernwin
import ida_pro

ida_auto.auto_wait()
actions = [(name, ida_kernwin.get_action_shortcut(name))
           for name in ida_kernwin.get_registered_actions()
           if ida_kernwin.get_action_shortcut(name) in ("Y", "y")]
pathlib.Path(__file__).with_name("check_y_actions.txt").write_text(
    repr(actions), encoding="utf-8")
ida_pro.qexit(0)
