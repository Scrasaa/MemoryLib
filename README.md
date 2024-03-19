# MemoryLib

MemoryLib is a comprehensive library designed for memory manipulation and pattern scanning in Windows applications. It provides a set of classes and functions to interact with the Windows API, allowing developers to perform tasks such as reading and writing memory, patching functions, and hooking into existing functions.

## Table of Contents

- [Getting Started](#getting-started)
- [Usage](#usage)
 - [CPatternScan](#cpatternscan)
 - [CMemory](#cmemory)
 - [CHook](#chook)
- [Acknowledgements](#acknowledgements)

## Getting Started

To use MemoryLib, you need to have a C++ development environment set up. This library is designed for use with Microsoft Visual Studio, but it can be used with other compilers that support C++11 or later.

1. **Include MemoryLib**: Add the MemoryLib header files to your project's include directories.

2. **Link Windows Libraries**: Ensure that your project links against the necessary Windows libraries (`Windows.h`, `TlHelp32.h`, etc.).

3. **Include MemoryLib in Your Code**

## Usage

### CPatternScan

`CPatternScan` is used for scanning memory patterns within a process. It provides methods for both in-process and external process pattern scanning.

- **InPatternScan**: Scans for a pattern within the current process.
- **ExPatternScan**: Scans for a pattern within a specified process.

 ### CHook

`CHook` extends `CMemory` and provides functionality for hooking functions.

- **Hook**: Hooks a function, redirecting its execution to a custom function.
- **Unhook**: Removes the hook.


### CMemory

`CMemory` provides a set of functions for reading and writing memory, patching functions, and managing modules.

### Functions

- **GetModuleBaseAddress**: Retrieves the base address of a module in a process.
 - Parameters:
    - `szModuleName`: The name of the module.
    - `procID`: The process ID.
 - Returns: The base address of the module.

- **GetProcessID**: Retrieves the process ID by its name.
 - Parameters:
    - `szProcessName`: The name of the process.
 - Returns: The process ID.

- **ReadMem**: Reads memory from a specified address.
 - Parameters:
    - `addy`: The memory address to read from.
    - `hProcess`: The handle to the process.
 - Returns: The value read from the memory address.

- **WriteMem**: Writes a value to a specified memory address.
 - Parameters:
    - `addy`: The memory address to write to.
    - `val`: The value to write.
    - `hProcess`: The handle to the process.

- **InNop**: Inserts NOP (No Operation) instructions within the current process.
 - Parameters:
    - `dst`: The destination address.
    - `iSize`: The size of the NOP instructions.

- **InPatch**: Patches a function within the current process.
 - Parameters:
    - `dst`: The destination address.
    - `src`: The source address.
    - `iSize`: The size of the patch.

- **ExPatch**: Patches a function within a specified process.
 - Parameters:
    - `dst`: The destination address.
    - `src`: The source address.
    - `iSize`: The size of the patch.
    - `hProcess`: The handle to the process.

- **ExNop**: Inserts NOP instructions within a specified process.
 - Parameters:
    - `dst`: The destination address.
    - `iSize`: The size of the NOP instructions.
    - `hProcess`: The handle to the process.

- **GetProcess**: Retrieves a handle to a process by its ID.
 - Parameters:
    - `procID`: The process ID.
 - Returns: The handle to the process.

- **GetVirtualFunctionAdd**: Retrieves the address of a virtual function.
 - Parameters:
    - `pVTable`: The virtual table pointer.
    - `iOffset`: The offset of the virtual function.
 - Returns: The address of the virtual function.

- **GetVirtualFunction**: Retrieves a virtual function.
 - Parameters:
    - `base`: The base address.
    - `iIndex`: The index of the virtual function.
    - `iOffset`: The offset of the virtual function.
 - Returns: The virtual function.

- **GetModuleEntry**: Retrieves a module entry by its name.
 - Parameters:
    - `szModuleName`: The name of the module.
    - `procID`: The process ID.
 - Returns: The module entry.

   ## Acknowledgements

I would like to express my heartfelt gratitude to the following community for their invaluable contributions, support and allowance to use their code:
- **GuidedHacking.com**: Without the support and collaboration of this incredible community, I wouldn't have been able to bring this together. Your contributions, insights, and feedback have been invaluable. Thank you for your time, expertise, and dedication.
