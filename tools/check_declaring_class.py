import os
import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import idautils
from PySide6 import QtCore, QtGui, QtWidgets

ida_auto.auto_wait()
output = pathlib.Path(__file__).with_name("check_declaring_class.txt")
source_ea = next(ea for ea in idautils.Functions()
                 if ida_funcs.get_func_name(ea) == "invoke_raw_vtable_slot_2")
targets = {ida_funcs.get_func_name(ea): ea for ea in idautils.Functions()
           if ida_funcs.get_func_name(ea) in
           ("demo_method_0", "demo_method_1", "demo_method_2", "scale_value")}
x_rows = []

def position_method():
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(x.line) for x in vu.cfunc.get_pseudocode()]
    line = next(i for i, text in enumerate(lines) if "object->" in text)
    place, _, _ = ida_kernwin.get_custom_viewer_place(vu.ct, False)
    simple = ida_kernwin.place_t.as_simpleline_place_t(place)
    simple.n = line
    ida_kernwin.jumpto(vu.ct, simple, 19, 0)
    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()
    vu.refresh_cpos(ida_hexrays.USE_KEYBOARD)
    return vu

def accept_first_row(attempt=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        QtCore.QTimer.singleShot(50, lambda: accept_first_row(attempt + 1))
        return
    view = dialog.findChild(QtWidgets.QTableView)
    if view is None:
        QtCore.QTimer.singleShot(50, lambda: accept_first_row(attempt + 1))
        return
    view.selectRow(0)
    dialog.accept()

rename_request = os.environ.get("PSEUDOCODE_XREFS_TEST_RENAME", "DeclaredMethod")
if rename_request == "__EMPTY__":
    rename_request = ""

def accept_rename(attempt=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        QtCore.QTimer.singleShot(50, lambda: accept_rename(attempt + 1))
        return
    editor = dialog.findChild(QtWidgets.QLineEdit)
    if editor is None:
        QtCore.QTimer.singleShot(50, lambda: accept_rename(attempt + 1))
        return
    editor.setText(rename_request)
    dialog.accept()

def capture_x(attempt=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        QtCore.QTimer.singleShot(50, lambda: capture_x(attempt + 1))
        return
    view = dialog.findChild(QtWidgets.QTableView)
    if view is None:
        QtCore.QTimer.singleShot(50, lambda: capture_x(attempt + 1))
        return
    model = view.model()
    for row in range(model.rowCount()):
        x_rows.append([str(model.index(row, col).data() or "")
                       for col in range(model.columnCount())])
    dialog.reject()

def run():
    vu = position_method()
    QtCore.QTimer.singleShot(100, accept_rename)
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
    QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyPress, QtCore.Qt.Key.Key_N,
        QtCore.Qt.KeyboardModifier.NoModifier, "n"))
    QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyRelease, QtCore.Qt.Key.Key_N,
        QtCore.Qt.KeyboardModifier.NoModifier, "n"))

    renamed = {name: ida_name.get_ea_name(ea) for name, ea in targets.items()}
    position_method()
    QtCore.QTimer.singleShot(100, capture_x)
    ida_kernwin.process_ui_action("pseudocode_xrefs:show_hierarchy_versions")

    classes = {row[0] for row in x_rows}
    if rename_request == "":
        rename_ok = (
            renamed["demo_method_0"] == "demo_method_0"
            and renamed["demo_method_1"].startswith("sub_")
            and renamed["demo_method_2"].startswith("sub_")
            and renamed["scale_value"] == "scale_value"
        )
        x_ok = classes == {"AActor", "ASomeActor"}
    elif rename_request == "AActor:HintedMethod":
        rename_ok = (
            renamed["demo_method_0"] == "demo_method_0"
            and renamed["demo_method_1"] == "AActor_HintedMethod"
            and renamed["demo_method_2"] == "ASomeActor_HintedMethod"
            and renamed["scale_value"] == "scale_value"
        )
        x_ok = classes == {"AActor", "ASomeActor"}
    elif rename_request == "AActor::SpawnPieceOfMeat":
        rename_ok = (
            renamed["demo_method_0"] == "demo_method_0"
            and renamed["demo_method_1"] == "_ZN6AActor16SpawnPieceOfMeatEv"
            and renamed["demo_method_2"] == "_ZN10ASomeActor16SpawnPieceOfMeatEv"
            and renamed["scale_value"] == "scale_value"
        )
        x_ok = classes == {"AActor", "ASomeActor"}
    elif rename_request.startswith("UObject::"):
        rename_ok = (
            renamed["demo_method_0"] == "UObject_BaseDeclared"
            and renamed["demo_method_1"] == "AActor_BaseDeclared"
            and renamed["demo_method_2"] == "ASomeActor_BaseDeclared"
            and renamed["scale_value"] == "USomeNetClass_BaseDeclared"
        )
        x_ok = classes == {"UObject", "AActor", "ASomeActor", "USomeNetClass"}
    else:
        rename_ok = (
            renamed["demo_method_0"] == "demo_method_0"
            and renamed["demo_method_1"] == "AActor_DeclaredMethod"
            and renamed["demo_method_2"] == "ASomeActor_DeclaredMethod"
            and renamed["scale_value"] == "scale_value"
        )
        x_ok = classes == {"AActor", "ASomeActor"}
    ok = rename_ok and x_ok
    output.write_text(
        f"renamed={renamed!r}\nclasses={classes!r}\n"
        f"rename_ok={rename_ok}\nx_ok={x_ok}\nok={ok}\n", encoding="utf-8")
    ida_pro.qexit(0 if ok else 1)

QtCore.QTimer.singleShot(1000, run)
