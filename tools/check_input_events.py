import ctypes
import pathlib
import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import ida_idaapi
import idautils

from PySide6 import QtCore, QtGui, QtWidgets


ida_auto.auto_wait()

source_ea = None
expected_ea = None
scale_value_ea = None
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    if "invoke_raw_vtable_slot_2" in name:
        source_ea = ea
    elif "demo_method_2" in name:
        expected_ea = ea
    elif name == "scale_value":
        scale_value_ea = ea

g_vtable_addend_ea = ida_name.get_name_ea(
    ida_idaapi.BADADDR,
    "g_vtable_addend",
)

output = pathlib.Path(__file__).with_name("check_input_events.txt")
if (
    source_ea is None
    or expected_ea is None
    or scale_value_ea is None
    or g_vtable_addend_ea == ida_idaapi.BADADDR
):
    output.write_text("required_functions_not_found\n", encoding="ascii")
    ida_pro.qexit(1)


def send_key(widget, key, modifiers=QtCore.Qt.KeyboardModifier.NoModifier, text=""):
    press = QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyPress,
        key,
        modifiers,
        text,
    )
    release = QtGui.QKeyEvent(
        QtCore.QEvent.Type.KeyRelease,
        key,
        modifiers,
        text,
    )
    return (
        QtWidgets.QApplication.sendEvent(widget, press)
        and QtWidgets.QApplication.sendEvent(widget, release)
    )


def double_click_column(viewport, line_index, column, user32):
    metrics = viewport.fontMetrics()
    character_width = metrics.horizontalAdvance("0")
    mouse_point = QtCore.QPoint(
        column * character_width + character_width // 2,
        line_index * metrics.height() + metrics.height() // 2,
    )
    global_point = viewport.mapToGlobal(mouse_point)
    cursor_set = user32.SetCursorPos(global_point.x(), global_point.y())
    QtWidgets.QApplication.processEvents()
    # Keep consecutive operand tests from being interpreted as one triple-click
    # sequence by Windows.
    time.sleep(user32.GetDoubleClickTime() / 1000.0 + 0.1)
    for _ in range(2):
        user32.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
        user32.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
        QtWidgets.QApplication.processEvents()
        time.sleep(0.05)
    QtWidgets.QApplication.processEvents()
    return cursor_set, ida_kernwin.get_screen_ea()


def run_test():
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()]
    method_token = "demo_method_2"
    line_index = next(
        (index for index, line in enumerate(lines) if method_token in line),
        None,
    )
    if line_index is None:
        output.write_text("named_vtable_method_not_found\n", encoding="ascii")
        ida_pro.qexit(1)
        return

    required_operands = ["object", "g_vtable_addend", "scale_value"]
    missing_operands = [operand for operand in required_operands if operand not in lines[line_index]]
    if missing_operands:
        output.write_text(
            f"complex_operands_not_found={missing_operands!r}\n",
            encoding="ascii",
        )
        ida_pro.qexit(1)
        return

    method_column = lines[line_index].index(method_token) + 2
    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
    widget.setFocus(QtCore.Qt.FocusReason.OtherFocusReason)
    QtWidgets.QApplication.processEvents()

    key_events_sent = send_key(
        widget,
        QtCore.Qt.Key.Key_Home,
        QtCore.Qt.KeyboardModifier.ControlModifier,
    )
    for _ in range(line_index):
        key_events_sent &= send_key(widget, QtCore.Qt.Key.Key_Down)
    for _ in range(method_column):
        key_events_sent &= send_key(widget, QtCore.Qt.Key.Key_Right)
    key_events_sent &= send_key(widget, QtCore.Qt.Key.Key_J, text="j")
    QtWidgets.QApplication.processEvents()
    key_screen_ea = ida_kernwin.get_screen_ea()

    mouse_vu = ida_hexrays.open_pseudocode(source_ea, 0)
    ida_kernwin.activate_widget(mouse_vu.ct, True)
    QtWidgets.QApplication.processEvents()
    mouse_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(mouse_vu.ct)
    viewport = mouse_widget.viewport()

    window = mouse_widget.window()
    window.raise_()
    window.activateWindow()
    QtWidgets.QApplication.processEvents()

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    window_handle = int(window.winId())
    foreground_handle = user32.GetForegroundWindow()
    foreground_thread = user32.GetWindowThreadProcessId(foreground_handle, None)
    current_thread = kernel32.GetCurrentThreadId()
    attached = user32.AttachThreadInput(current_thread, foreground_thread, True)
    user32.BringWindowToTop(window_handle)
    foreground_set = user32.SetForegroundWindow(window_handle)
    user32.SetActiveWindow(window_handle)
    if attached:
        user32.AttachThreadInput(current_thread, foreground_thread, False)

    method_cursor_set, method_double_click_screen_ea = double_click_column(
        viewport,
        line_index,
        method_column,
        user32,
    )

    operand_results = {}
    for operand in required_operands:
        operand_vu = ida_hexrays.open_pseudocode(source_ea, 0)
        ida_kernwin.activate_widget(operand_vu.ct, True)
        QtWidgets.QApplication.processEvents()
        operand_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(operand_vu.ct)
        cursor_set, screen_ea = double_click_column(
            operand_widget.viewport(),
            line_index,
            lines[line_index].index(operand) + 2,
            user32,
        )
        operand_results[operand] = (cursor_set, screen_ea)

    key_ok = key_events_sent and key_screen_ea == expected_ea
    method_double_click_ok = (
        foreground_set
        and method_cursor_set
        and method_double_click_screen_ea == expected_ea
    )
    expected_operand_targets = {
        "object": source_ea,
        "g_vtable_addend": g_vtable_addend_ea,
        "scale_value": scale_value_ea,
    }
    operand_double_click_ok = all(
        cursor_set and screen_ea == expected_operand_targets[operand]
        for operand, (cursor_set, screen_ea) in operand_results.items()
    )
    ok = key_ok and method_double_click_ok and operand_double_click_ok
    operand_output = "".join(
        f"{operand}_double_click_screen_ea=0x{screen_ea:X}\n"
        for operand, (_, screen_ea) in operand_results.items()
    )
    output.write_text(
        f"key_events_sent={key_events_sent}\n"
        f"key_screen_ea=0x{key_screen_ea:X}\n"
        f"key_ok={key_ok}\n"
        f"method_double_click_screen_ea=0x{method_double_click_screen_ea:X}\n"
        f"method_double_click_ok={method_double_click_ok}\n"
        + operand_output
        + f"operand_double_click_ok={operand_double_click_ok}\n"
        f"expected_ea=0x{expected_ea:X}\n"
        f"ok={ok}\n",
        encoding="ascii",
    )
    ida_pro.qexit(0 if ok else 1)


# The -S script runs before IDA shows its main window. Delay the input test
# until the pseudocode widget can receive real keyboard and mouse events.
QtCore.QTimer.singleShot(1000, run_test)
