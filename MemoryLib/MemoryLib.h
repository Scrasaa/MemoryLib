#pragma once

#include <Windows.h>

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <TlHelp32.h>
#include <string>
#include <exception>
#include "ntdll.h"

class CMemory
{
private:
	DWORD GetHashFromString(char* szString) const;

	LPCWSTR ConvertToLPCWSTR(const char* szModuleName) const;

	int CmpUnicodeStr(const WCHAR* substr, const WCHAR* mystr);
public:
	PEB* GetPEB();

	HMODULE ResolveModuleBaseAddressPEB(char* szModuleName) const;

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

	PDWORD GetFunctionAddressByHash(char* library, DWORD hash) const;

	void* GetFunctionAddress(char* MyNtdllFunction, PVOID MyDLLBaseAddress) const;

	template<typename T>
	T GetVTableFunction(void* pBase, int iIndex);

	static inline uintptr_t GetVirtual(void*** c, int idx)
	{
		return reinterpret_cast<uintptr_t>((*c)[idx]);
	}
};

class CPatternScan : public CMemory
{
private:
	char* ScanInWrapper(char* pattern, char* mask, char* begin, size_t size);

	void Parse(char* combo, char* pattern, char* mask);

	char* PatternScan(char* pattern, char* mask, char* begin, size_t size);

	char* TO_CHAR(wchar_t* string);

	LDR_DATA_TABLE_ENTRY* GetLDREntry(std::string name);

	char* ScanExWrapper(char* pattern, char* mask, char* begin, char* end, HANDLE hProc);

public:
	intptr_t InPatternScan(char* combopattern, std::string szModName);
	intptr_t InPatternScan(char* szPattern, char* szMask, std::string szModName);
	intptr_t ExPatternScan(char* combopattern, std::string szModName, uintptr_t procID, HANDLE hProcess);
};

// Lighter alternative to CPatternScan method
std::vector<int> ConvertPatternToBytes(const std::string& szPattern);
uint8_t* ScanPattern(const std::string& szSignature);


class CHook : public CMemory
{
private:
	BYTE m_Bytes[0x100]{ 0 };
	void* m_oFuncAddy = nullptr;
	size_t m_iLength = 0;
private:
	// pOriginalFunction should be the & address of the original function we set our gateway to
	void* Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength);
public:
	bool Hook(void* pOriginalFunctionAddress, uintptr_t pOriginalFunction, uintptr_t ourFunction, size_t iLength);
	bool Unhook();
};

class OffsetUpdateException : public std::exception {
public:
	explicit OffsetUpdateException(const std::string& message) : msg_(message) {}
	const char* what() const noexcept override {
		return msg_.c_str();
	}
private:
	std::string msg_;
};

bool IsPointerReadable(void* ptr);
