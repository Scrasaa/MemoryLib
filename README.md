# MemoryLib

MemoryLib is a comprehensive collection of functions designed for memory manipulation and pattern scanning in Windows applications. It provides a set of classes and functions to interact with the Windows API, allowing developers to perform tasks such as reading and writing memory, patching functions, and hooking into existing functions.

## Table of Contents

 - [CPatternScan](#cpatternscan)
 - [CMemory](#cmemory)
 - [CHook](#chook)
- [Acknowledgements](#acknowledgements)

### CPatternScan

`CPatternScan` is used for scanning memory patterns within a process. It provides methods for both in-process and external process pattern scanning.

- **InPatternScan**: Scans for a pattern within the current process.
- **ExPatternScan**: Scans for a pattern within a specified process.

 ### CHook

`CHook` extends `CMemory` and provides functionality for hooking functions.

- **Hook**: Hooks a function, redirecting its execution to a custom function.
- **Unhook**: Removes the hook.
- Only supporting x86 environment

### CMemory

`CMemory` provides a set of functions for reading and writing memory, patching functions, and managing modules.

## Plans

- Class for VMTHooks

   ## Acknowledgements

I would like to express my heartfelt gratitude to the following community for their invaluable contributions, support and allowance to use their code:
- **GuidedHacking.com**: 
