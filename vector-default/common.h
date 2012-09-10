#ifndef COMMON_H_
#define COMMON_H_

#ifdef WIN32
#include <Windows.h>
#else
#include "win32types.h"
#endif

inline DWORD alignTo( DWORD _size, DWORD _base_size )
{
	return ( ((_size + _base_size - 1) / _base_size) * _base_size );
}

inline DWORD alignToDWORD( DWORD _size )
{
	return (DWORD)( _size + ( sizeof(DWORD) - (_size % (sizeof(DWORD)))));
}

#define RALIGN(dwToAlign, dwAlignOn) ((dwToAlign%dwAlignOn == 0) ? dwToAlign : dwToAlign - (dwToAlign%dwAlignOn) + dwAlignOn)


#define EXE_TYPE_NSIS_INSTALLER 0x00000004
#define EXE_TYPE_WINZIP_SFX		0x00000008


#endif /* COMMON_H_ */