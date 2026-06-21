import pathlib

import ida_auto
import ida_funcs
import ida_kernwin
import ida_pro
import idautils
from PySide6 import QtCore, QtGui, QtWidgets

ida_auto.auto_wait()
output = pathlib.Path(__file__).with_name("check_disasm_x.txt")
source_ea = next(ea for ea in idautils.Functions()
                 if ida_funcs.get_func_name(ea) == "invoke_raw_vtable_slot_2")
actions = []
dialogs = []

class Hooks(ida_kernwin.UI_Hooks):
    def preprocess_action(self, name):
        actions.append(name)
        return 0

hooks = Hooks()
hooks.hook()

def close_dialog(attempt=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        if attempt < 20:
            QtCore.QTimer.singleShot(50, lambda: close_dialog(attempt + 1))
        return
    dialogs.append((dialog.windowTitle(), [x.text() for x in dialog.findChildren(QtWidgets.QLabel)]))
    dialog.reject()

def run():
    ok = False
    error = ""
    try:
        view = ida_kernwin.find_widget("IDA View-A")
        ida_kernwin.activate_widget(view, True)
        ida_kernwin.jumpto(source_ea)
        QtWidgets.QApplication.processEvents()
        widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(view)
        QtCore.QTimer.singleShot(100, close_dialog)
        QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
            QtCore.QEvent.Type.KeyPress, QtCore.Qt.Key.Key_X,
            QtCore.Qt.KeyboardModifier.NoModifier, "x"))
        QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
            QtCore.QEvent.Type.KeyRelease, QtCore.Qt.Key.Key_X,
            QtCore.Qt.KeyboardModifier.NoModifier, "x"))
        conflict = any("Conflicting shortcut" in " ".join(labels)
                       for _, labels in dialogs)
        ok = "pseudocode_xrefs:show_hierarchy_versions" not in actions and not conflict
    except Exception as exc:
        error = repr(exc)
    finally:
        output.write_text(
            f"actions={actions!r}\ndialogs={dialogs!r}\nerror={error!r}\nok={ok}\n",
            encoding="utf-8")
        ida_pro.qexit(0 if ok else 1)

QtCore.QTimer.singleShot(1000, run)
