// MemoryLib.cpp : Defines the functions for the static library.
//
#pragma warning ( disable : 6387 )
#pragma warning ( disable : 4244 )

#include "pch.h"
#include "framework.h"
#include "ntdll.h"
#include "MemoryLib.h"

// Before using external functions from this class, use GetProcessID first, to open the handle to the process!

bool CHook::Hook32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
{
    if (iLength > 5)
        return false;

    uintptr_t oldProtect{};

    VirtualProtect((LPVOID)pHookStart, iLength, PAGE_READWRITE, (PDWORD)&oldProtect);

    uintptr_t relativeAddress = (pHookStart - pOurFunction) - iLength;

    *(uintptr_t*)pHookStart = 0xE9; // JMP opcode /0xE9

    *(uintptr_t*)(pHookStart + 1) = relativeAddress;

    VirtualProtect((LPVOID)pHookStart, iLength, oldProtect, 0);

    return true;
}

bool CHook::Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
{
    if (iLength > 5)
        return false;

    uintptr_t oldProtect{};

    void* gateway = VirtualAlloc(0, sizeof(pOurFunction), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    VirtualProtect((LPVOID)pHookStart, iLength, PAGE_READWRITE, (PDWORD)&oldProtect);

    memcpy(gateway, (LPVOID)pHookStart, iLength);

    VirtualProtect((LPVOID)pHookStart, iLength, oldProtect, 0);

    if (Hook32(pHookStart, pOurFunction, iLength))
        return true;

    return false;
}

char* CPatternScan::ScanWrapper(char* pattern, char* mask, char* begin, size_t size)
{
    char* match{ nullptr };

    // Contains information about a range of pages in the virtual address space of a process. The VirtualQuery and VirtualQueryEx functions use this structure.
    MEMORY_BASIC_INFORMATION mbi{};

    // Iterates through memory regionsW
    for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
    {
        // Checks if the memory regions are accessable and readable, if not we skip
        if (!VirtualQuery(curr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        // If we found a valid memory region, we start our scan
        match = PatternScan(pattern, mask, curr, mbi.RegionSize);

        if (match != nullptr)
            break;
    }
    return match;
}

void CPatternScan::Parse(char* combo, char* pattern, char* mask)
{
    char lastChar = ' ';
    unsigned int j = 0;

    for (unsigned int i = 0; i < strlen(combo); i++)
    {
        if ((combo[i] == '?' || combo[i] == '*') && (lastChar != '?' && lastChar != '*'))
        {
            pattern[j] = mask[j] = '?';
            j++;
        }

        else if (isspace(lastChar))
        {
            pattern[j] = lastChar = (char)strtol(&combo[i], 0, 16);
            mask[j] = 'x';
            j++;
        }
        lastChar = combo[i];
    }
    pattern[j] = mask[j] = '\0';
}

char* CPatternScan::PatternScan(char* pattern, char* mask, char* begin, size_t size)
{
    size_t iPatternLength = strlen(mask);

    // Loop through memory region
    for (int i = 0; i < size; i++)
    {
        bool bFound = true;
        // Loop to check pattern and mask
        for (int j = 0; j < iPatternLength; j++)
        {
            // Check if it is not a wildcard and not matching pattern
            if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j))
            {
                bFound = false;
                break;
            }
        }

        if (bFound)
            return begin + i;

    }
    return nullptr;
}

char* CPatternScan::TO_CHAR(wchar_t* string)
{
    size_t len = wcslen(string) + 1;
    char* c_string = new char[len];
    size_t numCharsRead;
    // Converts a sequence of wide characters to a corresponding sequence of multibyte characters
    wcstombs_s(&numCharsRead, c_string, len, string, _TRUNCATE);
    return c_string;
}

// Structure with ProcessInformation
PEB* CPatternScan::GetPEB()
{
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsword(0x60);

#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif

    return peb;
}

LDR_DATA_TABLE_ENTRY* CPatternScan::GetLDREntry(std::string name)
{
    // Contains information about the loaded modules for the process
    LDR_DATA_TABLE_ENTRY* ldr = nullptr;

    PEB* peb = GetPEB();

    // Structure for a doubly linked list
    LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList; // inMemoryOrderModuleList = head of a doubly linked list that contains loaded moduels in the process!

    // Buffer of the linked list head
    LIST_ENTRY curr = head;

     // While begin != end, linked list (goes forward until last list is reached) -> just interates trhough MemoryOrderModuleList
    while (curr.Flink != head.Blink)
    {
        // Base Adress of the module struc
        LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->FullDllName.Buffer)
        {
            // Get module names
            char* cName = TO_CHAR(mod->BaseDllName.Buffer);

            // Comapre moduel names with our input module name
            if (_stricmp(cName, name.c_str()) == 0)
            {
                ldr = mod;
                break;
            }
            delete[] cName;
        }
        curr = *curr.Flink; // curr = next list
    }
    // Returns the structure of the found module
    return ldr;
}

intptr_t CPatternScan::PatternScanInternal(char* combopattern, std::string modName)
{
    // Getting the struc module informations of our module
    LDR_DATA_TABLE_ENTRY* ldr = GetLDREntry(modName);

    char pattern[100];
    char mask[100];
    Parse(combopattern, pattern, mask);

    char* match = ScanWrapper(pattern, mask, (char*)ldr->DllBase, ldr->SizeOfImage);

    return (intptr_t)match;
}

uintptr_t CMemory::GetModuleBaseAddress(const char* szModuleName, uintptr_t procID)
{
    uintptr_t moduleBaseAddress = NULL;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, procID);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 me32{};

        me32.dwSize = sizeof(me32);

        if (Module32First(hSnap, &me32))
        {
            do
            {
                if (!_strcmpi((const char*)me32.szExePath, szModuleName))
                {
                    moduleBaseAddress = (uintptr_t)me32.modBaseAddr;
                    break;
                }

            } while (Module32Next(hSnap, &me32));
        }
    }

    if (hSnap)
        CloseHandle(hSnap);

    return moduleBaseAddress;
}

uintptr_t CMemory::GetProcessID(const char* szProcessName)
{
    uintptr_t procID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(pe32);

        if (Process32First(hSnap, &pe32))
        {
            do
            {
                if (!_strcmpi(szProcessName, (const char*)pe32.szExeFile))
                {
                    procID = pe32.th32ProcessID;
                    break;
                }

            } while (Process32Next(hSnap, &pe32));
        }
    }

    if (hSnap)
        CloseHandle(hSnap);

    return procID;
}

template <typename value>
uintptr_t CMemory::ReadMem(uintptr_t addy, HANDLE hProcess)
{
    value val{};
    DWORD oldProtect;
    VirtualProtectEx(hProcess, dst, iSize, PAGE_EXECUTE_READ, &oldProtect); // If it doesnt work, try out PAGE_EXECUTE_READWRITE
    ReadProcessMemory(hProcess, addy, &val, sizeof(val), NULL);
    VirtualProtectEx(hProcess, dst, iSize, oldProtect, NULL);
    return val;
}

template <typename value>
void CMemory::WriteMem(uintptr_t addy, value val, HANDLE hProcess)
{
    DWORD oldProtect;
    VirtualProtectEx(hProcess, dst, iSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, addy, &val, sizeof(val), NULL);
    VirtualProtectEx(hProcess, dst, iSize, oldProtect, NULL);
}

void CMemory::InNop(LPVOID dst, size_t iSize)
{
    DWORD oldProtect;
    VirtualProtect(dst, iSize, PAGE_READWRITE, &oldProtect);
    memset(dst, 0x90, iSize);
    VirtualProtect(dst, iSize, oldProtect, &oldProtect);
}

void CMemory::InPatch(LPVOID dst, LPVOID src, size_t iSize)
{
    DWORD oldProtect;
    VirtualProtect(dst, iSize, PAGE_READWRITE, &oldProtect);
    memcpy(dst, src, iSize);
    VirtualProtect(dst, iSize, oldProtect, &oldProtect);
}

void CMemory::ExPatch(LPVOID dst, LPVOID src, size_t iSize, HANDLE hProcess)
{
    DWORD oldProtect;
    VirtualProtectEx(hProcess, dst, iSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, dst, src, iSize, NULL);
    VirtualProtectEx(hProcess, dst, iSize, oldProtect, NULL);
}

void CMemory::ExNop(LPVOID dst, size_t iSize, HANDLE hProcess)
{
    BYTE* nopArray = new BYTE[iSize];
    memset(nopArray, 0x90, iSize);

    ExPatch(dst, nopArray, iSize, hProcess);

    delete[] nopArray;
}

HANDLE CMemory::GetProcess(uintptr_t procID)
{
    HANDLE hProcess = 0;

    while (!hProcess)
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procID);

     return hProcess;
}
