import ctypes
import pathlib
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import idautils

from PySide6 import QtCore, QtGui, QtWidgets


ida_auto.auto_wait()

source_ea = None
targets = {}
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    if name == "invoke_raw_vtable_slot_2":
        source_ea = ea
    elif name in ("demo_method_0", "demo_method_1", "demo_method_2", "scale_value"):
        targets[name] = ea

output = pathlib.Path(__file__).with_name("check_inheritance.txt")
if source_ea is None or len(targets) != 4:
    output.write_text("required_functions_not_found\n", encoding="ascii")
    ida_pro.qexit(1)


def send_key(widget, key, modifiers=QtCore.Qt.KeyboardModifier.NoModifier, text=""):
    press = QtGui.QKeyEvent(QtCore.QEvent.Type.KeyPress, key, modifiers, text)
    release = QtGui.QKeyEvent(QtCore.QEvent.Type.KeyRelease, key, modifiers, text)
    return (
        QtWidgets.QApplication.sendEvent(widget, press)
        and QtWidgets.QApplication.sendEvent(widget, release)
    )


def position_cursor(widget, line_index, column):
    for _ in range(20):
        send_key(widget, QtCore.Qt.Key.Key_Up)
    send_key(widget, QtCore.Qt.Key.Key_Home)
    for _ in range(line_index):
        send_key(widget, QtCore.Qt.Key.Key_Down)
    for _ in range(column):
        send_key(widget, QtCore.Qt.Key.Key_Right)
    QtWidgets.QApplication.processEvents()


def foreground_window(widget):
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    window = widget.window()
    window.raise_()
    window.activateWindow()
    QtWidgets.QApplication.processEvents()
    handle = int(window.winId())
    foreground = user32.GetForegroundWindow()
    foreground_thread = user32.GetWindowThreadProcessId(foreground, None)
    current_thread = kernel32.GetCurrentThreadId()
    attached = user32.AttachThreadInput(current_thread, foreground_thread, True)
    user32.BringWindowToTop(handle)
    user32.SetForegroundWindow(handle)
    user32.SetActiveWindow(handle)
    if attached:
        user32.AttachThreadInput(current_thread, foreground_thread, False)
    return user32


def double_click(viewport, line_index, column, user32):
    metrics = viewport.fontMetrics()
    width = metrics.horizontalAdvance("0")
    point = QtCore.QPoint(
        column * width + width // 2,
        line_index * metrics.height() + metrics.height() // 2,
    )
    global_point = viewport.mapToGlobal(point)
    user32.SetCursorPos(global_point.x(), global_point.y())
    QtWidgets.QApplication.processEvents()
    time.sleep(user32.GetDoubleClickTime() / 1000.0 + 0.1)
    for _ in range(2):
        user32.mouse_event(0x0002, 0, 0, 0, 0)
        user32.mouse_event(0x0004, 0, 0, 0, 0)
        QtWidgets.QApplication.processEvents()
        time.sleep(0.05)
    QtWidgets.QApplication.processEvents()


def accept_rename_dialog():
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        QtCore.QTimer.singleShot(50, accept_rename_dialog)
        return
    editor = dialog.findChild(QtWidgets.QLineEdit)
    if editor is None:
        QtCore.QTimer.singleShot(50, accept_rename_dialog)
        return
    editor.setText("HierarchyMethod")
    buttons = dialog.findChild(QtWidgets.QDialogButtonBox)
    ok_button = (
        buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Ok)
        if buttons is not None
        else None
    )
    if ok_button is not None:
        ok_button.click()
    else:
        dialog.accept()


def run_test():
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()]
    line_index = next(
        (index for index, line in enumerate(lines) if "object->demo_method_1" in line),
        None,
    )
    if line_index is None:
        output.write_text("actor_method_not_rendered\n", encoding="ascii")
        ida_pro.qexit(1)
        return
    column = lines[line_index].index("demo_method_1") + 2

    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
    user32 = foreground_window(widget)
    double_click(widget.viewport(), line_index, column, user32)
    double_click_target = ida_kernwin.get_screen_ea()

    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
    position_cursor(widget, line_index, column)
    QtCore.QTimer.singleShot(100, accept_rename_dialog)
    send_key(widget, QtCore.Qt.Key.Key_N, text="n")
    QtWidgets.QApplication.processEvents()

    expected_names = {
        "demo_method_0": "UObject_HierarchyMethod",
        "demo_method_1": "AActor_HierarchyMethod",
        "demo_method_2": "ASomeActor_HierarchyMethod",
        "scale_value": "USomeNetClass_HierarchyMethod",
    }
    renamed = {
        old_name: ida_name.get_ea_name(targets[old_name])
        for old_name in expected_names
    }
    refreshed_lines = [
        ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()
    ]
    rendered = next(
        (line for line in refreshed_lines if "object->AActor_HierarchyMethod" in line),
        None,
    )

    vtable_targets = {
        class_name: ida_bytes.get_qword(vtable_ea + 2 * 8)
        for class_name, vtable_ea in {
            "UObject": 0x140023100,
            "AActor": 0x140023120,
            "ASomeActor": 0x140023140,
            "USomeNetClass": 0x140023160,
        }.items()
    }
    exact_navigation_ok = double_click_target == targets["demo_method_1"]
    rename_ok = all(
        renamed[old_name] == expected_name
        for old_name, expected_name in expected_names.items()
    )
    slots_unchanged = (
        vtable_targets["UObject"] == targets["demo_method_0"]
        and vtable_targets["AActor"] == targets["demo_method_1"]
        and vtable_targets["ASomeActor"] == targets["demo_method_2"]
        and vtable_targets["USomeNetClass"] == targets["scale_value"]
    )
    ok = exact_navigation_ok and rename_ok and slots_unchanged and rendered is not None
    output.write_text(
        f"double_click_target=0x{double_click_target:X}\n"
        f"expected_actor_target=0x{targets['demo_method_1']:X}\n"
        f"exact_navigation_ok={exact_navigation_ok}\n"
        f"renamed={renamed!r}\n"
        f"rename_ok={rename_ok}\n"
        f"slots_unchanged={slots_unchanged}\n"
        f"rendered={rendered!r}\n"
        f"ok={ok}\n",
        encoding="ascii",
    )
    ida_pro.qexit(0 if ok else 1)


QtCore.QTimer.singleShot(1000, run_test)
