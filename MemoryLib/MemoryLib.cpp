#pragma warning ( disable : 6387 )
#pragma warning ( disable : 4244 )

#include "ntdll.h"
#include "MemoryLib.h"

// Before using external functions from this class, use GetProcessID first, to open the handle to the process!
void* CHook::Detour32(uintptr_t pHookStart, uintptr_t pOurFunction, size_t iLength)
{
	if (iLength < 5)
		return nullptr;

	// Allocate gateway
	void* pGateway = VirtualAlloc(0, iLength + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pGateway)
		return nullptr;

	// Write Stolen Bytes to gateway
	memcpy_s(pGateway, iLength, reinterpret_cast<void*>(pHookStart), iLength);

	uintptr_t gatewayRelativeAdd = (pHookStart - reinterpret_cast<uintptr_t>(pGateway)) - 5;

	// JMP instrc at the end of gateway
	*reinterpret_cast<char*>((reinterpret_cast<uintptr_t>(pGateway) + iLength)) = 0xE9;

	// Write add of the gateway to the jump
	*reinterpret_cast<uintptr_t*>((reinterpret_cast<uintptr_t>(pGateway) + iLength + 1)) = gatewayRelativeAdd;

	// Detour begins here
	DWORD oldProtect{};

	VirtualProtect((LPVOID)pHookStart, iLength, PAGE_EXECUTE_READWRITE, &oldProtect);

	uintptr_t relativeAddress = (pOurFunction - pHookStart) - 5;

	*reinterpret_cast<char*>(pHookStart) = 0xE9; // JMP opcode /0xE9

	*reinterpret_cast<uintptr_t*>(pHookStart + 1) = relativeAddress;

	if (!VirtualProtect((LPVOID)pHookStart, iLength, oldProtect, &oldProtect))
	{
		// Handle protection restoration error
		VirtualFree(pGateway, 0, MEM_RELEASE);
		return nullptr;
	}

	return pGateway;
}

bool CHook::Hook(void* pOriginalFunctionAddress, uintptr_t pOriginalFunction, uintptr_t ourFunction, size_t iLength)
{
	if (!pOriginalFunctionAddress || !pOriginalFunction)
		return false;

	this->m_oFuncAddy = pOriginalFunctionAddress;
	this->m_iLength = iLength;

	this->InPatch(this->m_Bytes, this->m_oFuncAddy, this->m_iLength);

	auto pDetour = reinterpret_cast<uintptr_t>(Detour32(reinterpret_cast<uintptr_t>(pOriginalFunctionAddress), ourFunction, iLength));

	if (!pDetour)
		return false;

	*reinterpret_cast<uintptr_t*>(pOriginalFunction) = pDetour;

	return true;
}

bool CHook::Unhook()
{
	this->InPatch(this->m_oFuncAddy, this->m_Bytes, this->m_iLength);

	return true;
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

intptr_t CPatternScan::InPatternScan(char* szPattern, char* szMask, std::string szModName)
{
	// Getting the struc module informations of our module
	LDR_DATA_TABLE_ENTRY* ldr = GetLDREntry(szModName);

	char* match = ScanInWrapper(szPattern, szMask, (char*)ldr->DllBase, ldr->SizeOfImage);

	return (intptr_t)match;
}

std::vector<int> ConvertPatternToBytes(const std::string& szPattern) {
    std::vector<int> bytes;
    const char* start = szPattern.c_str();
    const char* end = start + szPattern.length();

    for (const char* current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?')
                ++current;
            bytes.push_back(-1); // Wildcard
        }
        else {
            bytes.push_back(static_cast<int>(std::strtoul(current, const_cast<char**>(&current), 16)));
        }
    }

    return bytes;
}

uint8_t* ScanPattern(const std::string& szSignature) {

    HMODULE moduleHandle = GetModuleHandleA(nullptr);
    if (!moduleHandle)
        return nullptr;

    auto const* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleHandle);
    auto const* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(moduleHandle) + dosHeader->e_lfanew
        );

    const size_t moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
    auto* moduleBytes = reinterpret_cast<uint8_t*>(moduleHandle);

    // Convert the pattern into byte format.
    std::vector<int> patternBytes = ConvertPatternToBytes(szSignature);
    const size_t patternLength = patternBytes.size();

    // Scan the module's memory for the pattern.
    for (size_t i = 0; i < moduleSize - patternLength; ++i) {
        bool matchFound = true;

        // Compare memory bytes to the pattern.
        for (size_t j = 0; j < patternLength; ++j) {
            if (moduleBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) {
                matchFound = false;
                break;
            }
        }
        if (matchFound)
            return &moduleBytes[i];
    }
    return nullptr;
}

LPCWSTR CMemory::ConvertToLPCWSTR(const char* szModuleName) const
{
	if (!szModuleName)
		return nullptr;

	// Calculate the required size for the wide string
	int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, nullptr, 0);
	if (wideCharSize <= 0)
		return nullptr; // Handle error

	// Allocate memory for the wide string
	wchar_t* wideString = new wchar_t[wideCharSize];

	// Perform the conversion
	MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, wideString, wideCharSize);

	return wideString; // Return the converted string, need to handle memory deallocation
}

int CMemory::CmpUnicodeStr(const WCHAR* substr, const WCHAR* mystr)
{
	// Convert both strings to lowercase using _wcslwr_s
	WCHAR lowerSubstr[MAX_PATH];
	WCHAR lowerMystr[MAX_PATH];

	// Copy and lowercase the input strings
	wcscpy_s(lowerSubstr, MAX_PATH, substr);
	wcscpy_s(lowerMystr, MAX_PATH, mystr);
	_wcslwr_s(lowerSubstr, MAX_PATH);
	_wcslwr_s(lowerMystr, MAX_PATH);

	// Check if the substring exists in the main string
	return (wcsstr(lowerMystr, lowerSubstr) != NULL) ? 1 : 0;
}

PEB* CMemory::GetPEB()
{
#ifdef _WIN64
	auto peb = (PEB*)__readgsword(0x60);

#else
	auto peb = (PEB*)__readfsdword(0x30);
#endif

	return peb;
}

HMODULE CMemory::ResolveModuleBaseAddressPEB(char* szModuleName) const
{
	// Convert the input module name to LPCWSTR
	LPCWSTR lModuleName = ConvertToLPCWSTR(szModuleName);
	if (!lModuleName)
		return nullptr;
	// move getpeb to cmemory and use it instead
	// Access the PEB structure
	auto pPeb = GetPEB();

	PEB_LDR_DATA* pLdr = pPeb->Ldr;
	LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
	LIST_ENTRY* pCurrent = pListHead->Flink;

	// Iterate through the loaded modules
	while (pCurrent != pListHead) {
		// Get the current LDR_DATA_TABLE_ENTRY
		auto pEntry = CONTAINING_RECORD(pCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Compare the module names safely
		if (pEntry->BaseDllName.Buffer != NULL) {
			if (_wcsicmp(pEntry->BaseDllName.Buffer, lModuleName) == 0) {
				// Found the DLL, return its base address
				delete[] lModuleName; // Clean up
				return (HMODULE)pEntry->DllBase; // Return the base address
			}
		}

		// Move to the next entry
		pCurrent = pCurrent->Flink;
	}

	// Clean up if not found
	delete[] lModuleName; // Clean up
	return nullptr;
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

DWORD CMemory::GetHashFromString(char* szString) const
{
	size_t iLength = strnlen_s(szString, 50);
	DWORD hash = 0x35;

	for (size_t i = 0; i < iLength; i++)
	{
		hash += (hash * 0xab10f29f + szString[i]) & 0xffffff;
	}

	return hash;
}

PDWORD CMemory::GetFunctionAddressByHash(char* library, DWORD hash) const
{
	PDWORD functionAddress = nullptr;

	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);

	auto dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	auto imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)libraryBase + dosHeader->e_lfanew);

	DWORD exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	auto imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	auto addresOfFunctionsRVA = (PDWORD)((DWORD)libraryBase + imageExportDirectory->AddressOfFunctions);
	auto addressOfNamesRVA = (PDWORD)((DWORD)libraryBase + imageExportDirectory->AddressOfNames);
	auto addressOfNameOrdinalsRVA = (PWORD)((DWORD)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
	// If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD functionNameVA = (DWORD)libraryBase + functionNameRVA;
		auto* functionName = (char*)functionNameVA;
		DWORD functionAddressRVA = 0;

		// Calculate hash for this exported function
		DWORD functionNameHash = GetHashFromString(functionName);

		// If hash for CreateThread is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD)libraryBase + functionAddressRVA);
			//printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}

void* CMemory::GetFunctionAddress(char* MyNtdllFunction, PVOID MyDLLBaseAddress) const
{
	DWORD j;
	uintptr_t RVA = 0;

	//Parse DLL loaded in memory
	const auto BaseDLLAddr = (LPVOID)MyDLLBaseAddress;
	auto pImgDOSHead = (PIMAGE_DOS_HEADER)BaseDLLAddr;
	auto pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseDLLAddr + pImgDOSHead->e_lfanew);

	//Get the Export Directory Structure
	auto pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr + pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//Get the functions RVA array
	auto Address = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfFunctions);

	//Get the function names array
	auto Name = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNames);

	//get the Ordinal array
	auto Ordinal = (PWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNameOrdinals);

	//Get RVA of the function from the export table
	for (j = 0; j < pImgExpDir->NumberOfNames; j++) {
		if (!strcmp(MyNtdllFunction, (char*)BaseDLLAddr + Name[j])) {
			//if function name found, we retrieve the RVA
			RVA = (uintptr_t)((LPBYTE)Address[Ordinal[j]]);
			break;
		}
	}

	if (RVA) {
		//Compute RVA to find the current address in the process
		uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
		uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
		return (PVOID)TrueAddress;
	}
	else {
		return (PVOID)RVA;
	}
}
