/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C depacker, header file
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 *
 */

#ifndef DEPACK_H_INCLUDED
#define DEPACK_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR (-1)
#endif

/* internal data structure */
typedef struct {
	const unsigned char *source;
	unsigned char *destination;
	unsigned int tag;
	unsigned int bitcount;
} APDEPACKDATA;

/*
; header format:
;
;  offs  size    data
; --------------------------------------
;    0   dword   tag ('AP32')
;    4   dword   header_size (24 bytes)
;    8   dword   packed_size
;   12   dword   packed_crc
;   16   dword   orig_size
;   20   dword   orig_crc
*/

typedef struct {
	DWORD tag;
	DWORD header_size;
	DWORD packed_size;
	DWORD packed_crc;
	DWORD orig_size;
	DWORD orig_crc;
} APLIBHEADER, *PALIBHEADER;

__forceinline static int aP_getbit(APDEPACKDATA *ud)
{
	unsigned int bit;

	/* check if tag is empty */
	if (!ud->bitcount--)
	{
		/* load next tag */
		ud->tag = *ud->source++;
		ud->bitcount = 7;
	}

	/* shift bit out of tag */
	bit = (ud->tag >> 7) & 0x01;
	ud->tag <<= 1;

	return bit;
}

__forceinline static unsigned int aP_getgamma(APDEPACKDATA *ud)
{
	unsigned int result = 1;

	/* input gamma2-encoded bits */
	do {
		result = (result << 1) + aP_getbit(ud);
	} while (aP_getbit(ud));

	return (result);
}

//__forceinline unsigned int aP_depack(const void *source, void *destination)
unsigned int aP_depack(const void *source, void *destination)
{
	APDEPACKDATA ud;
	unsigned int offs, len, R0, LWM;
	int done;
	int i;

	ud.source = (const unsigned char *) source;
	ud.destination = (unsigned char *) destination;
	ud.bitcount = 0;

	LWM = 0;
	done = 0;

	/* first byte verbatim */
	*ud.destination++ = *ud.source++;

	/* main decompression loop */
	while (!done)
	{
		if (aP_getbit(&ud))
		{
			if (aP_getbit(&ud))
			{
				if (aP_getbit(&ud))
				{
					offs = 0;

					for (i = 4; i; i--) offs = (offs << 1) + aP_getbit(&ud);

					if (offs)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					} else {
						*ud.destination++ = 0x00;
					}

					LWM = 0;

				} else {

					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs)
					{
						for (; len; len--)
						{
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					} else done = 1;

					R0 = offs;
					LWM = 1;
				}

			} else {

				offs = aP_getgamma(&ud);

				if ((LWM == 0) && (offs == 2))
				{
					offs = R0;

					len = aP_getgamma(&ud);

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

				} else {

					if (LWM == 0) offs -= 3; else offs -= 2;

					offs <<= 8;
					offs += *ud.source++;

					len = aP_getgamma(&ud);

					if (offs >= 32000) len++;
					if (offs >= 1280) len++;
					if (offs < 128) len += 2;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
				}

				LWM = 1;
			}

		} else {

			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	return ud.destination - (unsigned char *) destination;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DEPACK_H_INCLUDED */
