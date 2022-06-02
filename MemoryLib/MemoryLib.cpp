// MemoryLib.cpp : Defines the functions for the static library.
//
#pragma warning ( disable : 6387 )
#pragma warning ( disable : 4244 )

#include "pch.h"
#include "framework.h"
#include "ntdll.h"
#include "MemoryLib.h"

// Before using external functions from this class, use GetProcessID first, to open the handle to the process!

void* CHook::Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
{
    if (iLength < 5)
        return nullptr;

    // Allocate gateway
    BYTE* pGateway = (BYTE*)VirtualAlloc(0, iLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write Stolen Bytes to gatewa<y
    memcpy_s(pGateway, iLength, (LPVOID)pHookStart, iLength);

    uintptr_t gatewayRelativeAdd = pHookStart - (uintptr_t)pGateway - 5;

    // JMP instrc at the end of gateway
    *(pGateway + iLength) = 0xE9;

    // Write add of the gateway to the jump
    *(uintptr_t*)((uintptr_t)pGateway + iLength + 1) = gatewayRelativeAdd;

    // Detour
    DWORD oldProtect{};

    VirtualProtect((LPVOID)pHookStart, iLength, PAGE_EXECUTE_READWRITE, &oldProtect);

    uintptr_t relativeAddress = (pOurFunction - pHookStart) - 5;

    *(uintptr_t*)pHookStart = 0xE9; // JMP opcode /0xE9

    *(uintptr_t*)(pHookStart + 1) = relativeAddress;

    VirtualProtect((LPVOID)pHookStart, iLength, oldProtect, 0);

    return pGateway;
}

void* CHook::Detour64(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
{
    if (iLength < 13)
        return nullptr;

    uint8_t absJumpInstructions[] =
    {
      0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r10, addr
      0x41, 0xFF, 0xE2 //jmp r10
    };

    DWORD oldProc{};

    memcpy(&absJumpInstructions[2], &pOurFunction, sizeof(pOurFunction));
    memcpy(&pHookStart, &absJumpInstructions, sizeof(absJumpInstructions));

    VirtualProtect((LPVOID)pHookStart, iLength, PAGE_EXECUTE_READWRITE, &oldProc);

    void* pTrampoline = VirtualAlloc(0, iLength + sizeof(absJumpInstructions), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    DWORD64 retto = (DWORD64)pHookStart + iLength;

    // trampoline
    memcpy(absJumpInstructions + 6, &retto, 8);
    memcpy((void*)((DWORD_PTR)pTrampoline), &pHookStart, iLength);
    memcpy((void*)((DWORD_PTR)pTrampoline + iLength), absJumpInstructions, sizeof(absJumpInstructions));

    // orig
    memcpy(absJumpInstructions + 6, &pOurFunction, 8);
    memcpy(&pHookStart, absJumpInstructions, sizeof(absJumpInstructions));

    for (int i = 13; i < iLength; i++)
    {
        *(BYTE*)((DWORD_PTR)pHookStart + i) = 0x90;
    }

    VirtualProtect(&pHookStart, iLength, oldProc, &oldProc);
    return (void*)((DWORD_PTR)pTrampoline);
}

bool CHook::Hook(void* pOriginalFunctionAddress, uintptr_t pOriginalFunction, uintptr_t ourFunction, size_t iLength)
{
    if (!pOriginalFunctionAddress)
        return false;

    // Create a copy of the functionPointer
    void** pBuffer = (void**)pOriginalFunction;

    // Make the function pointer point to the original function address
    *pBuffer = (void**)pOriginalFunctionAddress;

    // Make the function pointer point to our gateway
    #ifdef _WIN64
        *pBuffer = (void*)(Detour64((uintptr_t)*pBuffer, ourFunction, iLength));
    #else 
        *pBuffer = (void*)(Detour32((uintptr_t)*pBuffer, ourFunction, iLength));
    #endif

    return true;
}

bool CHook::Unhook()
{
    memcpy(this->m_oFuncAddy, this->m_Bytes, this->m_iLength);

    return true;
}

CHook::CHook(void* pOriginalFunctionAddress, size_t iLength)
{
    this->m_oFuncAddy = pOriginalFunctionAddress;
    this->m_iLength = iLength;

    memcpy(this->m_Bytes, this->m_oFuncAddy, this->m_iLength);
}

char* CPatternScan::ScanInWrapper(char* pattern, char* mask, char* begin, size_t size)
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

char* CPatternScan::ScanExWrapper(char* pattern, char* mask, char* begin, char* end, HANDLE hProcess)
{
    char* match = nullptr;
    SIZE_T bytesRead;
    DWORD oldprotect;
    char* buffer = nullptr;
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    char* curr = begin;

    for (char* curr = begin; curr < end; curr += mbi.RegionSize)
    {
        if (!VirtualQueryEx(hProcess, curr, &mbi, sizeof(mbi))) return nullptr;
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        // char* of the memory region
        buffer = new char[mbi.RegionSize];

        if (VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
        {
            // Reads the current memory region
            ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

            char* internalAddr = PatternScan(pattern, mask, buffer, (unsigned int)bytesRead);

            if (internalAddr != nullptr)
            {
                //calculate from internal to external
                match = curr + (uintptr_t)(internalAddr - buffer);
                break;
            }
        }
    }
    delete[] buffer;
    return (char*)match;
}

intptr_t CPatternScan::ExPatternScan(char* combopattern, std::string szModName, uintptr_t procID, HANDLE hProcess)
{
    char pattern[100];
    char mask[100];
    Parse(combopattern, pattern, mask);

    CMemory pMemory{};

    MODULEENTRY32 modEntry = pMemory.GetModuleEntry(szModName.c_str(), procID);

    char* begin = (char*)modEntry.modBaseAddr;
    char* end = begin + modEntry.modBaseSize;

    char* match = ScanExWrapper(pattern, mask, begin, end, hProcess);

    return (intptr_t)match;
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

intptr_t CPatternScan::InPatternScan(char* combopattern, std::string szModName)
{
    // Getting the struc module informations of our module
    LDR_DATA_TABLE_ENTRY* ldr = GetLDREntry(szModName);

    char pattern[100];
    char mask[100];
    Parse(combopattern, pattern, mask);

    char* match = ScanInWrapper(pattern, mask, (char*)ldr->DllBase, ldr->SizeOfImage);

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

MODULEENTRY32 CMemory::GetModuleEntry(const char* szModuleName, uintptr_t procID)
{
    MODULEENTRY32 mod32{ 0 };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, procID);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        mod32.dwSize = sizeof(mod32);

        if (Module32First(hSnap, &mod32))
        {
            do
            {
                if (!_strcmpi((const char*)mod32.szModule, szModuleName))
                {
                    break;
                }

            } while (Module32Next(hSnap, &mod32));
        }
    }

    if (hSnap)
        CloseHandle(hSnap);

    return mod32;
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
    VirtualProtectEx(hProcess, (LPVOID)addy, sizeof(addy), PAGE_EXECUTE_READ, &oldProtect); // If it doesnt work, try out PAGE_EXECUTE_READWRITE
    ReadProcessMemory(hProcess, addy, &val, sizeof(val), NULL);
    VirtualProtectEx(hProcess, (LPVOID)addy, sizeof(addy), oldProtect, NULL);
    return val;
}

template <typename value>
void CMemory::WriteMem(uintptr_t addy, value val, HANDLE hProcess)
{
    DWORD oldProtect;
    VirtualProtectEx(hProcess, (LPVOID)addy, sizeof(addy), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, addy, &val, sizeof(val), NULL);
    VirtualProtectEx(hProcess, (LPVOID)addy, sizeof(addy), oldProtect, NULL);
}

void CMemory::InNop(LPVOID dst, size_t iSize)
{
    DWORD oldProtect;
    VirtualProtect(dst, iSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memset(dst, 0x90, iSize);
    VirtualProtect(dst, iSize, oldProtect, &oldProtect);
}

void CMemory::InPatch(LPVOID dst, LPVOID src, size_t iSize)
{
    DWORD oldProtect;
    VirtualProtect(dst, iSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy_s(dst, iSize, src, iSize);
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
