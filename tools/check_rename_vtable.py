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

source_ea = None
target_ea = None
scale_value_ea = None
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    if "invoke_raw_vtable_slot_2" in name:
        source_ea = ea
    elif name == "demo_method_2":
        target_ea = ea
    elif name == "scale_value":
        scale_value_ea = ea

output = pathlib.Path(__file__).with_name("check_rename_vtable.txt")
if source_ea is None or target_ea is None or scale_value_ea is None:
    output.write_text("required_functions_not_found\n", encoding="ascii")
    ida_pro.qexit(1)

processed_actions = []
dialog_details = []
pending_name = "renamed_vtable_method_2"
dialog_poll_count = 0


class ActionHooks(ida_kernwin.UI_Hooks):
    def preprocess_action(self, name):
        processed_actions.append(name)
        return 0


action_hooks = ActionHooks()
action_hooks.hook()


def send_key(widget, key, modifiers=QtCore.Qt.KeyboardModifier.NoModifier, text=""):
    press = QtGui.QKeyEvent(QtCore.QEvent.Type.KeyPress, key, modifiers, text)
    release = QtGui.QKeyEvent(QtCore.QEvent.Type.KeyRelease, key, modifiers, text)
    return (
        QtWidgets.QApplication.sendEvent(widget, press)
        and QtWidgets.QApplication.sendEvent(widget, release)
    )


def accept_rename_dialog():
    global dialog_poll_count
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        dialog_poll_count += 1
        if dialog_poll_count < 20:
            QtCore.QTimer.singleShot(50, accept_rename_dialog)
        return
    editor = dialog.findChild(QtWidgets.QLineEdit)
    if editor is None:
        QtCore.QTimer.singleShot(50, accept_rename_dialog)
        return
    dialog_details.append(
        {
            "class": dialog.metaObject().className(),
            "title": dialog.windowTitle(),
            "editors": [
                (item.objectName(), item.text(), item.isVisible())
                for item in dialog.findChildren(QtWidgets.QLineEdit)
            ],
            "buttons": [
                (item.objectName(), item.text(), item.isVisible())
                for item in dialog.findChildren(QtWidgets.QPushButton)
            ],
        }
    )
    editor.setText(pending_name)
    button_box = dialog.findChild(QtWidgets.QDialogButtonBox)
    ok_button = (
        button_box.button(QtWidgets.QDialogButtonBox.StandardButton.Ok)
        if button_box is not None
        else None
    )
    if ok_button is not None:
        ok_button.click()
    else:
        dialog.accept()


def run_test():
    global pending_name, dialog_poll_count
    vu = ida_hexrays.open_pseudocode(source_ea, 0)
    lines = [ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()]
    line_index = next(
        (index for index, line in enumerate(lines) if "demo_method_2" in line),
        None,
    )
    if line_index is None:
        output.write_text("named_method_not_found\n", encoding="ascii")
        ida_pro.qexit(1)
        return

    column = lines[line_index].index("demo_method_2") + 2
    ida_kernwin.activate_widget(vu.ct, True)
    QtWidgets.QApplication.processEvents()
    widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
    widget.setFocus(QtCore.Qt.FocusReason.OtherFocusReason)
    send_key(
        widget,
        QtCore.Qt.Key.Key_Home,
        QtCore.Qt.KeyboardModifier.ControlModifier,
    )
    for _ in range(line_index):
        send_key(widget, QtCore.Qt.Key.Key_Down)
    for _ in range(column):
        send_key(widget, QtCore.Qt.Key.Key_Right)

    QtCore.QTimer.singleShot(100, accept_rename_dialog)
    key_sent = send_key(widget, QtCore.Qt.Key.Key_N, text="n")
    QtWidgets.QApplication.processEvents()

    renamed_name = ida_name.get_ea_name(target_ea)
    refreshed_lines = [
        ida_lines.tag_remove(line.line) for line in vu.cfunc.get_pseudocode()
    ]
    rendered = next(
        (line for line in refreshed_lines if "renamed_vtable_method_2" in line),
        None,
    )

    native_rename_ok = False
    if rendered is not None:
        refreshed_line_index = refreshed_lines.index(rendered)
        native_column = rendered.index("scale_value") + 2
        for _ in range(20):
            send_key(widget, QtCore.Qt.Key.Key_Up)
        send_key(widget, QtCore.Qt.Key.Key_Home)
        for _ in range(refreshed_line_index):
            send_key(widget, QtCore.Qt.Key.Key_Down)
        for _ in range(native_column):
            send_key(widget, QtCore.Qt.Key.Key_Right)
        QtWidgets.QApplication.processEvents()
        pending_name = "renamed_scale_value"
        dialog_poll_count = 0
        QtCore.QTimer.singleShot(100, accept_rename_dialog)
        send_key(widget, QtCore.Qt.Key.Key_N, text="n")
        QtWidgets.QApplication.processEvents()
        native_rename_ok = (
            ida_name.get_ea_name(scale_value_ea) == "renamed_scale_value"
        )

    ok = (
        key_sent
        and renamed_name == "renamed_vtable_method_2"
        and rendered is not None
        and native_rename_ok
    )
    output.write_text(
        f"key_sent={key_sent}\n"
        f"renamed_name={renamed_name!r}\n"
        f"rendered={rendered!r}\n"
        f"native_rename_ok={native_rename_ok}\n"
        f"processed_actions={processed_actions!r}\n"
        f"dialog_details={dialog_details!r}\n"
        f"ok={ok}\n",
        encoding="ascii",
    )
    ida_pro.qexit(0 if ok else 1)


QtCore.QTimer.singleShot(1000, run_test)
