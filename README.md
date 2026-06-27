# IDA-VTable-Utility

IDA-VTable-Utility improves virtual-function calls in the Hex-Rays pseudocode
view. It recognizes direct and indirect VTable access, renders readable method
expressions, and provides inheritance-aware navigation, renaming, prototypes,
and cross-references.

### NOTE: This project is fully AI generated, I don't take any credit for anything in here.

## Features

### Virtual-call recognition

The plugin recognizes raw and typed VTable expressions such as:

```cpp
(*(*object + 0x10))(object, 0);
(*(object->VTable + 2))(object, 0);
```

They are rendered as `object->VTABLE[0x2](object, 0)`, or as
`object->MethodName(object, 0)` when the slot points to a named function.

Split loads are tracked as well:

```cpp
v19 = *(this->VTable + 0x163);
v19(this, ...);
```

The assignment is rendered as `v19 = &this->VTABLE[0x163]`, or
`v19 = &this->MethodName` for a named entry. For an untyped `void *this`, the
plugin can infer the class from the containing `Class::Method` function when a
matching named VTable exists.

VTable symbols may use the `_vft`, `_Vft`, or `_VFT` suffix.

### Pseudocode actions

Actions activate only when the cursor is on a recognized VTable method or
index. IDA's normal shortcuts remain available everywhere else.

| Input | Action |
| --- | --- |
| Double-click or `J` | Open the current class's implementation in pseudocode. |
| `I` | Toggle the displayed slot between VTable index and byte offset. |
| `N` | Rename or unname the slot's hierarchy implementations. |
| `Y` | Edit the current implementation's prototype and apply it to matching hierarchy implementations. |
| `X` | Show implementations in the current class hierarchy. |
| `K` | Show ordinary cross-references for the resolved target. |

The hierarchy window contains one row per class. Clicking a column selects its
destination:

- **Class** opens the class in Local Types.
- **VTABLE** opens the exact VTable slot in disassembly.
- **Implementation** opens the implementation in pseudocode.
- **Address** opens the target address in disassembly.

### Inheritance-aware edits

A plain name entered with `N` treats the current static class as the declaration
class and updates only that class and its descendants. This prevents a newly
introduced derived-class method from writing beyond shorter base VTables.

- `AActor::MyFunction` sets `AActor` as the declaration class and applies basic
  Itanium ABI mangling to each implementation.
- `AActor:MyFunction` uses `AActor` only as a declaration hint; the prefix is not
  part of the saved function name.
- An empty name removes the names across the same hierarchy boundary.

You can also right-click a recognized method and choose
**IDA-VTable-Utility → Set virtual method declaring class...**. Declaration
boundaries are stored in the IDB.

Basic Itanium nested method names are decoded for display. For example,
`_ZN16ATICharacterBase20execSpawnPieceOfMeatEv` is shown as
`SpawnPieceOfMeat`; an override may be qualified with its declaring class when
needed.

`Y` starts with the actual prototype from the current class's VTable target. The
edited declaration is then applied only to implementations inside the selected
declaration boundary. When the declaration has an explicit first pointer
argument, each implementation gets that `this`/`self` argument retargeted to the
implementation class.

## Requirements

- IDA Professional 9.2 or newer
- Hex-Rays decompiler
- IDA SDK configured through the `IDASDK` environment variable
- CMake 3.27 or newer
- Visual Studio with C++ build tools on Windows

## Build

```powershell
$env:IDASDK = "C:\path\to\idasdk"
cmake -S . -B build
cmake --build build --config Release
```

On Windows, the build installs the DLL and metadata into IDA's user plugin
directory automatically. The internal DLL name, action IDs, metadata keys, and
install folder remain `pseudocode_xrefs` for upgrade compatibility.

## Demo and diagnostics

The `demo` directory contains small databases and sources covering direct calls,
indirect loads, inheritance, navigation, rename, and prototype propagation.
Supporting IDAPython checks are in `tools`.

Diagnostic output is written to:

```text
%APPDATA%\Hex-Rays\IDA Pro\pseudocode_xrefs.log
```

The legacy log filename is retained so existing troubleshooting scripts keep
working.
