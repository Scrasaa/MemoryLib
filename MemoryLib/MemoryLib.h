#pragma once

#include "pch.h"
#include "framework.h"
#include "ntdll.h"

class CMemory;

class CHook
{
private:
    BYTE m_Bytes[10]{};
    void* m_oFuncAddy = nullptr;
    size_t m_iLength = 0;
private:
    void* Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength);
    void* Detour64(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength);
public:
    bool Hook(void* pOriginalFunctionAddress, uintptr_t pOriginalFunction, uintptr_t ourFunction, size_t iLength);
    bool Unhook();
    CHook(void* pOriginalFunctionAddress, size_t iLength);
};

class CPatternScan
{
private:
    char* ScanInWrapper(char* pattern, char* mask, char* begin, size_t size);

    void Parse(char* combo, char* pattern, char* mask);

    char* PatternScan(char* pattern, char* mask, char* begin, size_t size);

    char* TO_CHAR(wchar_t* string);

    PEB* GetPEB();

    LDR_DATA_TABLE_ENTRY* GetLDREntry(std::string name);

    char* ScanExWrapper(char* pattern, char* mask, char* begin, char* end, HANDLE hProc);

public:
    intptr_t InPatternScan(char* combopattern, std::string szModName);
    intptr_t ExPatternScan(char* combopattern, std::string szModName, uintptr_t procID, HANDLE hProcess);
};

class CMemory
{
public:
    uintptr_t GetModuleBaseAddress(const char* szModuleName, uintptr_t procID);

    uintptr_t GetProcessID(const char* szProcessName);

    template <typename value>
    uintptr_t ReadMem(uintptr_t addy, HANDLE hProcess);

    template <typename value>
    void WriteMem(uintptr_t addy, value val, HANDLE hProcess);

    void InNop(LPVOID dst, size_t iSize);

    void InPatch(LPVOID dst, LPVOID src, size_t iSize);

    void ExPatch(LPVOID dst, LPVOID src, size_t iSize, HANDLE hProcess);

    void ExNop(LPVOID dst, size_t iSize, HANDLE hProcess);

    HANDLE GetProcess(uintptr_t procID);

    MODULEENTRY32 GetModuleEntry(const char* szModuleName, uintptr_t procID);

};