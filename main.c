/* WorkItemLoadLibrary.c by @rad9800
 * Credit goes to:
 * - Peter Winter-Smith (@peterwintrsmith)
 * - Proofpoint threatinsight team for their detailed analysis
 *
 * Loads a DLL by queuing a work item (RtlQueueWorkItem/) with
 * the address of LoadLibraryW and a pointer to the buffer
 * 
 * Modified by @Kr0ff
 * To support custom implementation of GetModuleHandle that accept hashed strings (CRC32B)
 * 
 */

#include "headers.h"
#include <stdio.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif

#define STRUCTS

#define HCRC32_NTDLL	0xffffffff84c05e40 //(DWORD64)
#define HCRC32_DBGHELP	0xffffffff031756a1 //(DWORD64)

#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

// Very nice way of casting a function to be used 
#define IMPORTAPI( DLLFILE, DLLNAME_HASH, FUNCNAME, RETTYPE, ...)\
typedef RETTYPE( WINAPI* type##FUNCNAME )( __VA_ARGS__ );\
type##FUNCNAME FUNCNAME = (type##FUNCNAME)GetProcAddress((LoadLibraryW(DLLFILE), pGetModuleHandle(DLLNAME_HASH)), #FUNCNAME);

// Source: https://stackoverflow.com/a/21001712
DWORD64 crc32bw(LPWSTR str) {
	DWORD64 byte, crc, mask;
	int i = 0, j;
	crc = 0xFFFFFFFF;
	while (str[i] != 0) {
		byte = str[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {
			mask = -((int)crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i = i + 1;
	}
	return ~crc;
}

HMODULE pGetModuleHandle(DWORD64 lpModuleNameCRC32Hash) {

	HMODULE moduleHandle = NULL;
  PPEB			pPeb = (PEB*)(__readgsqword(0x60)); // only X64

	PPEB_LDR_DATA pLdr = pPeb->LdrData;
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;

	while (pLdrDataTableEntry) {
		if (pLdrDataTableEntry->FullDllName.Length != NULL) {
			DWORD64 dllHash = crc32bw((LPWSTR)pLdrDataTableEntry->FullDllName.Buffer);

			if (dllHash == lpModuleNameCRC32Hash) {
#ifdef STRUCTS
				return (HMODULE)(pLdrDataTableEntry->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pLdrDataTableEntry->Reserved2[0];
#endif // STRUCTS
			}

		} else { break; }
    
		pLdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pLdrDataTableEntry);
	
  }

	return NULL;
}

HMODULE queueLoadLibrary(WCHAR* libraryName, DWORD64 ModuleHash, BOOL swtch)
{
	IMPORTAPI(L"NTDLL.dll", HCRC32_NTDLL, NtWaitForSingleObject, NTSTATUS, HANDLE, BOOLEAN, PLARGE_INTEGER);
	IMPORTAPI(L"NTDLL.dll", HCRC32_NTDLL, RtlQueueWorkItem, NTSTATUS, PVOID, PVOID, ULONG);
	IMPORTAPI(L"NTDLL.dll", HCRC32_NTDLL, RtlRegisterWait, NTSTATUS, PHANDLE, HANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG);

	LARGE_INTEGER timeout;
	timeout.QuadPart = -500000;

	if (swtch)
	{
		printf("[!] Calling RtlQueueWorkItem\n");
    
		if (NT_SUCCESS(RtlQueueWorkItem(&LoadLibraryW, (PVOID)libraryName, WT_EXECUTEDEFAULT)))
		{	
			NtWaitForSingleObject(NtCurrentProcess(), FALSE, &timeout);
		}
		printf("\n-- PAUSED! Press enter to continue --\n");
		getchar();
	}
	else
	{
		printf("[!] Calling RtlRegisterWait\n");
    
		HANDLE newWaitObject;
		HANDLE eventObject = CreateEventW(NULL, FALSE, FALSE, NULL);

		if (NT_SUCCESS(RtlRegisterWait(&newWaitObject, eventObject, LoadLibraryW, (PVOID)libraryName, 0, WT_EXECUTEDEFAULT)))
		{
			NtWaitForSingleObject(eventObject, FALSE, &timeout);
		}

		printf("\n-- PAUSED! Press enter to continue --\n");
		getchar();
	}

	return pGetModuleHandle(ModuleHash);
}

int main()
{
	WCHAR libraryName[] = L"DBGHELP.dll";
	
	printf("[MAIN] PAUSED! Press enter to continue.... \n");
	getchar();
	
	HMODULE moduleHandle = queueLoadLibrary(libraryName, HCRC32_DBGHELP, TRUE);

	printf("[+] Module address -> 0x%p\n", moduleHandle);

	return 0;
}
