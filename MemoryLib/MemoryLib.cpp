// MemoryLib.cpp : Defines the functions for the static library.
//
#pragma warning ( disable : 6387 )
#pragma warning ( disable : 4244 )

#include "pch.h"
#include "framework.h"

class CMemory
{
private:
    uintptr_t procID = NULL;
    HANDLE hHandle = NULL;
public:

    ~CMemory()
    {
        CloseHandle(hHandle);
    }

    uintptr_t GetModuleBaseAddress(const char* szModuleName)
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

    uintptr_t GetProcessID(const char* szProcessName)
    {
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
                        hHandle = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
                        break;
                    }

                } while (Process32Next(hSnap, &pe32));
            }
        }

        if (hSnap)
            CloseHandle(hSnap);

        return procID;
    }

    bool Hook32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
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

    bool Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
    {
        if (iLength > 5)
            return false;

        uintptr_t oldProtect{};

        void* gateway = VirtualAlloc(0, sizeof(pOurFunction), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        VirtualProtect((LPVOID)pHookStart, iLength, PAGE_READWRITE, (PDWORD)&oldProtect);

        memcpy(gateway, (LPVOID)pHookStart, iLength);

        VirtualProtect((LPVOID)pHookStart, iLength, oldProtect, 0);

        Hook32(pHookStart, pOurFunction, iLength);

        return true;
    }

    template <typename value>
    uintptr_t ReadMem(uintptr_t addy)
    {
        value val{};
        ReadProcessMemory(hHandle, addy, &val, sizeof(val), NULL);
        return val;
    }

    template <typename value>
    void WriteMem(uintptr_t addy, value val)
    {
        WriteProcessMemory(hHandle, addy, &val, sizeof(val), NULL);
    }


};






