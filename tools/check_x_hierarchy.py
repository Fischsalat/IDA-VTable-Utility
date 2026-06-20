import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idautils
from PySide6 import QtCore, QtGui, QtWidgets

ida_auto.auto_wait()
output = pathlib.Path(__file__).with_name("check_x_hierarchy.txt")
source_ea = next((ea for ea in idautils.Functions()
                  if ida_funcs.get_func_name(ea) == "invoke_raw_vtable_slot_2"), None)
actions = []
dialogs = []

class Hooks(ida_kernwin.UI_Hooks):
    def preprocess_action(self, name):
        actions.append(name)
        return 0

hooks = Hooks()
hooks.hook()

def send_key(widget, key, text=""):
    QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyPress, key, QtCore.Qt.KeyboardModifier.NoModifier, text))
    QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyRelease, key, QtCore.Qt.KeyboardModifier.NoModifier, text))

def position(vu, widget, line, column):
    place, _, _ = ida_kernwin.get_custom_viewer_place(vu.ct, False)
    simple_place = ida_kernwin.place_t.as_simpleline_place_t(place)
    simple_place.n = line
    ida_kernwin.jumpto(vu.ct, simple_place, column, 0)
    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()

def inspect_and_close(label, attempts=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        if attempts < 40:
            QtCore.QTimer.singleShot(50, lambda: inspect_and_close(label, attempts + 1))
        return
    rows = []
    view = dialog.findChild(QtWidgets.QTableView)
    if view is not None:
        model = view.model()
        for row in range(model.rowCount()):
            rows.append([str(model.index(row, col).data() or "")
                         for col in range(model.columnCount())])
    dialogs.append((label, dialog.windowTitle(), rows))
    dialog.reject()

def run():
    if source_ea is None:
        output.write_text("source missing\n")
        ida_pro.qexit(1)
        return
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(x.line) for x in vu.cfunc.get_pseudocode()]
    line = next(i for i, text in enumerate(lines) if "object->" in text)
    ida_kernwin.activate_widget(vu.ct, True)
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)

    method = next(name for name in ("AActor_HierarchyMethod", "demo_method_1")
                  if name in lines[line])
    position(vu, widget, line, lines[line].index(method) + 2)
    QtCore.QTimer.singleShot(100, lambda: inspect_and_close("method"))
    send_key(widget, QtCore.Qt.Key.Key_X, "x")
    QtWidgets.QApplication.processEvents()

    position(vu, widget, line, lines[line].index("g_vtable_addend") + 2)
    QtCore.QTimer.singleShot(100, lambda: inspect_and_close("global"))
    send_key(widget, QtCore.Qt.Key.Key_X, "x")
    QtWidgets.QApplication.processEvents()

    method_dialog = next((d for d in dialogs if d[0] == "method"), None)
    global_dialog = next((d for d in dialogs if d[0] == "global"), None)
    method_rows = method_dialog[2] if method_dialog else []
    classes = {row[0] for row in method_rows if row[0]}
    method_ok = (
        classes == {"UObject", "AActor", "ASomeActor"}
        and len(method_rows) == 3
        and all(all(cell for cell in row) for row in method_rows)
    )
    native_ok = global_dialog is not None and "hierarchy:" not in global_dialog[1]
    ok = method_ok and native_ok
    output.write_text(
        f"actions={actions!r}\nmethod={method_dialog!r}\nglobal={global_dialog!r}\n"
        f"method_ok={method_ok}\nnative_ok={native_ok}\nok={ok}\n", encoding="utf-8")
    ida_pro.qexit(0 if ok else 1)

QtCore.QTimer.singleShot(1000, run)
