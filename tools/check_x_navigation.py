import ctypes
import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idautils
from PySide6 import QtCore, QtTest, QtWidgets

ida_auto.auto_wait()
output = pathlib.Path(__file__).with_name("check_x_navigation.txt")
source_ea = next(ea for ea in idautils.Functions()
                 if ida_funcs.get_func_name(ea) == "invoke_raw_vtable_slot_2")
results = []

def choose_cell(row, column, attempts=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        if attempts < 40:
            QtCore.QTimer.singleShot(50, lambda: choose_cell(row, column, attempts + 1))
        return
    view = dialog.findChild(QtWidgets.QTableView)
    if view is None:
        QtCore.QTimer.singleShot(50, lambda: choose_cell(row, column, attempts + 1))
        return
    index = view.model().index(row, column)
    view.setCurrentIndex(index)
    rect = view.visualRect(index)
    point = QtCore.QPoint(rect.left() + 8, rect.center().y())
    global_point = view.viewport().mapToGlobal(point)
    ctypes.windll.user32.SetCursorPos(global_point.x(), global_point.y())
    QtTest.QTest.mouseDClick(
        view.viewport(), QtCore.Qt.MouseButton.LeftButton,
        QtCore.Qt.KeyboardModifier.NoModifier, point)

def activate(column):
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(x.line) for x in vu.cfunc.get_pseudocode()]
    line = next(i for i, text in enumerate(lines) if "object->" in text)
    method = next(name for name in ("AActor_HierarchyMethod", "demo_method_1")
                  if name in lines[line])
    place, _, _ = ida_kernwin.get_custom_viewer_place(vu.ct, False)
    simple = ida_kernwin.place_t.as_simpleline_place_t(place)
    simple.n = line
    ida_kernwin.jumpto(vu.ct, simple, lines[line].index(method) + 2, 0)
    ida_kernwin.activate_widget(vu.ct, True)
    QtCore.QTimer.singleShot(100, lambda: choose_cell(0, column))
    ida_kernwin.process_ui_action("pseudocode_xrefs:show_hierarchy_versions")
    QtWidgets.QApplication.processEvents()
    widget = ida_kernwin.get_current_widget()
    results.append((column, ida_kernwin.get_widget_type(widget),
                    ida_kernwin.get_widget_title(widget), ida_kernwin.get_screen_ea()))

def run():
    for column in range(4):
        activate(column)
    class_ok = "Local Types" in results[0][2]
    vtable_ok = results[1][3] == 0x140023120 + 0x10
    implementation_ok = results[2][1] == ida_kernwin.BWN_PSEUDOCODE
    address_ok = results[3][3] == 0x140001020 and results[3][1] != ida_kernwin.BWN_PSEUDOCODE
    ok = class_ok and vtable_ok and implementation_ok and address_ok
    output.write_text(
        f"results={results!r}\nclass_ok={class_ok}\nvtable_ok={vtable_ok}\n"
        f"implementation_ok={implementation_ok}\naddress_ok={address_ok}\nok={ok}\n",
        encoding="utf-8")
    ida_pro.qexit(0 if ok else 1)

QtCore.QTimer.singleShot(1000, run)
