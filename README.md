# Pseudocode Xrefs

An IDA Pro C++ plugin that opens IDA's native cross-reference chooser for the
pseudocode item under the keyboard cursor when `K` is pressed.

The action is enabled only in Hex-Rays pseudocode views. Target resolution and
xref display are delegated to IDA's built-in `JumpOpXref` action, so the plugin
follows IDA's native behavior for functions, globals, strings, structure
members, and other supported pseudocode operands.

The plugin also rewrites raw virtual-call expressions such as
`*(*object + 0x10)(object, 0)` as
`object->VTABLE[0x2](object, 0)` on 64-bit databases. If the object has a named
type, its matching `TypeName_vft`/`TypeName_Vft` symbol exists, and the selected
entry points to a named function, the token is rendered using that function's
name instead (for example, `object->demo_method_2(...)`).

## Requirements

- IDA Pro 9.2 or newer with a Hex-Rays decompiler
- IDA SDK 9.2 or newer
- CMake 3.27 or newer
- A C++17 compiler (Visual Studio 2022 on Windows)

## Build

Initialize the SDK's CMake submodule once:

```powershell
git -C C:\path\to\ida-sdk submodule update --init --recursive
```

Configure and build:

```powershell
$env:IDASDK = "C:\path\to\ida-sdk"
cmake -S . -B build
cmake --build build --config Release
```

The SDK build helpers place the resulting plugin under the configured
`IDABIN\plugins` directory. On Windows, this project also copies each successful
plugin build to
`%APPDATA%\Hex-Rays\IDA Pro\plugins\pseudocode_xrefs`, so a newly started IDA
session loads the current build automatically.

## Demo Database

The repository includes:

- `demo/pseudocode_xrefs_demo.exe`, a small program with clear function and
  global-data cross-references.
- `demo/pseudocode_xrefs_demo.i64`, its pre-analyzed IDA database.
- `demo/pseudocode_xrefs_vtable_demo.i64`, the latest database with a raw
  virtual-call example in `invoke_raw_vtable_slot_2`.
- `demo/pseudocode_xrefs_vtable_jump_demo.i64`, a typed-object database for
  testing `J` navigation through `VftJumpType_vft`.
- `demo/pseudocode_xrefs_complex_args_demo.i64`, a typed-object database whose
  raw virtual call passes both `&g_vtable_addend` and the `scale_value` function
  pointer.

Open the `.i64` file, decompile `main`, place the cursor on a function or global
item, and press `K`.

For the VTABLE rewrite, open `pseudocode_xrefs_vtable_demo.i64` and decompile
`invoke_raw_vtable_slot_2`.

For VTABLE navigation, open `pseudocode_xrefs_vtable_jump_demo.i64`, decompile
`anonymous_namespace_::invoke_raw_vtable_slot_2`, place the cursor on
`VTABLE[0x2]`, and press `J` or double-click the token. The plugin should jump
to `demo_method_2`.

For operand hit-testing, open `pseudocode_xrefs_complex_args_demo.i64` and
decompile `invoke_raw_vtable_slot_2`. The call is rendered as:

```cpp
return object->demo_method_2(object, &g_vtable_addend, scale_value);
```

Only double-clicking `demo_method_2` should jump to its implementation.
Double-clicking `object`, `g_vtable_addend`, or `scale_value` is left to IDA's
native navigation.

With named-method rendering enabled, place the cursor on the method name and:

- Press `I` to show its VTABLE index and original byte offset.
- Press `J` or double-click to jump to the implementation.
- Press `N` to rename the function stored in that VTABLE slot.
- Press `K` for the existing pseudocode xref action.

If the object is typed as `SomeType *` and a symbol named `SomeType_vft`
exists, placing the cursor on `object->VTABLE[index]` and pressing `J`, or
double-clicking that token, reads the vtable entry and jumps to the referenced
function.

Diagnostic information for `J` navigation is appended to
`%APPDATA%\Hex-Rays\IDA Pro\pseudocode_xrefs.log`.

## Interaction test

`tools/check_input_events.py` drives IDA's actual pseudocode widget. It sends a
Qt `J` key event and Windows double-clicks on `demo_method_2`, `object`,
`g_vtable_addend`, and `scale_value`. It verifies that the key and method click
navigate to `demo_method_2`, while the operand clicks do not trigger VTABLE
navigation. Run it with the GUI executable because mouse events are unavailable
in `idat.exe` batch mode:

```powershell
& "C:\Program Files\IDA Professional 9.2\ida.exe" -A `
  "-SC:\path\to\IDAClickAndVFT\tools\check_input_events.py" `
  "C:\path\to\IDAClickAndVFT\demo\pseudocode_xrefs_complex_args_demo.i64"
```
