#ifndef _RC4_H
#define _RC4_H

#include <iomanip>
#include <string>
#include <sstream>
//#include "smc.h"

#define RC4KEYLEN 64

#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0)

void rc4_encrypt(
	const unsigned char *key, 
	size_t keylen, 
	size_t skip,
	unsigned char *data, 
	size_t data_len);


#endif /* _RC4_H */