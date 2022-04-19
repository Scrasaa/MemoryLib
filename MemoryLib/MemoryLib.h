#pragma once

#include "pch.h"
#include "framework.h"
#include "ntdll.h"

class CHook
{
private:
    bool Hook32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength);
public:
    bool Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength);
};

class CPatternScan
{
private:
    char* ScanWrapper(char* pattern, char* mask, char* begin, size_t size);

    void Parse(char* combo, char* pattern, char* mask);

    char* PatternScan(char* pattern, char* mask, char* begin, size_t size);

    char* TO_CHAR(wchar_t* string);

    PEB* GetPEB();

    LDR_DATA_TABLE_ENTRY* GetLDREntry(std::string name);

public:
    intptr_t PatternScanInternal(char* combopattern, std::string modName);
};

class CMemory : public CPatternScan, public CHook
{
private:
    ~CMemory();
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

};