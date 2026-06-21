import pathlib

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_pro
import ida_typeinf
import idautils
from PySide6 import QtCore, QtGui, QtWidgets

ida_auto.auto_wait()
output = pathlib.Path(__file__).with_name("check_y_signature.txt")
source_ea = next(ea for ea in idautils.Functions()
                 if ida_funcs.get_func_name(ea) == "invoke_raw_vtable_slot_2")
details = []

def inspect_dialog(attempt=0):
    dialog = QtWidgets.QApplication.activeModalWidget()
    if dialog is None:
        QtCore.QTimer.singleShot(50, lambda: inspect_dialog(attempt + 1))
        return
    details.append({
        "title": dialog.windowTitle(),
        "line_edits": [x.text() for x in dialog.findChildren(QtWidgets.QLineEdit)],
        "plain_edits": [x.toPlainText() for x in dialog.findChildren(QtWidgets.QPlainTextEdit)],
        "text_edits": [x.toPlainText() for x in dialog.findChildren(QtWidgets.QTextEdit)],
    })
    editors = dialog.findChildren(QtWidgets.QLineEdit)
    if editors:
        editors[0].setText(
            "long long __fastcall demo_method_1(VftJumpType *self, int changed);")
        dialog.accept()
    else:
        dialog.reject()

def run():
    ok = False
    rendered_type = ""
    error = ""
    try:
        vu = ida_hexrays.open_pseudocode(source_ea, 0)
        lines = [ida_lines.tag_remove(x.line) for x in vu.cfunc.get_pseudocode()]
        line = next(i for i, text in enumerate(lines) if "object->" in text)
        place, _, _ = ida_kernwin.get_custom_viewer_place(vu.ct, False)
        simple = ida_kernwin.place_t.as_simpleline_place_t(place)
        simple.n = line
        ida_kernwin.jumpto(vu.ct, simple, 19, 0)
        ida_kernwin.activate_widget(vu.ct, True)
        QtWidgets.QApplication.processEvents()
        QtCore.QTimer.singleShot(100, inspect_dialog)
        widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vu.ct)
        QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
            QtCore.QEvent.Type.KeyPress, QtCore.Qt.Key.Key_Y,
            QtCore.Qt.KeyboardModifier.NoModifier, "y"))
        QtWidgets.QApplication.sendEvent(widget, QtGui.QKeyEvent(
            QtCore.QEvent.Type.KeyRelease, QtCore.Qt.Key.Key_Y,
            QtCore.Qt.KeyboardModifier.NoModifier, "y"))
        rendered = {}
        for name, ea in {
            "base": 0x140001000,
            "selected": 0x140001020,
            "child": 0x140001040,
        }.items():
            tif = ida_typeinf.tinfo_t()
            rendered[name] = tif.dstr() if ida_nalt.get_tinfo(tif, ea) else ""
        rendered_type = repr(rendered)
        still_pseudocode = (
            ida_kernwin.get_widget_type(ida_kernwin.get_current_widget())
            == ida_kernwin.BWN_PSEUDOCODE
        )
        ok = (
            bool(details)
            and "demo_method_1" in details[0]["line_edits"][0]
            and "char method()" not in details[0]["line_edits"][0]
            and "int changed" in rendered["selected"]
            and "int changed" in rendered["child"]
            and "int changed" not in rendered["base"]
            and still_pseudocode
        )
    except Exception as exc:
        error = repr(exc)
    finally:
        output.write_text(
            f"details={details!r}\ntype={rendered_type!r}\nerror={error!r}\nok={ok}\n",
            encoding="utf-8")
        ida_pro.qexit(0 if ok else 1)

QtCore.QTimer.singleShot(1000, run)
