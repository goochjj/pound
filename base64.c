#include <string.h>
#include <stdio.h>

/*
 * This code is based on code at
 * http://www.episec.com/people/edelkind/arc/c/misc/base64.c
 * by Ari Edelkind
 *
 * Released into public domain
 *
 * Changes and enhancements made by Joseph Gooch <mrwizard@dok.org>
 */
static char b64string[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

long base64_encode (char *const to, const char *const from, unsigned int len)
{
	const char *fromp = from;
	char *top = to;
	unsigned char cbyte;
	unsigned char obyte;
	char end[3];

	for (; len >= 3; len -= 3) {
		cbyte = *fromp++;
		*top++ = b64string[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 4);			/* 0000 1111 */
		*top++ = b64string[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		cbyte = *fromp++;
		obyte |= (cbyte >> 6);			/* 0000 0011 */
		*top++ = b64string[(int)obyte];
		*top++ = b64string[(int)(cbyte & 0x3F)];/* 0011 1111 */
	}

	if (len) {
		end[0] = *fromp++;
		if (--len) end[1] = *fromp++; else end[1] = 0;
		end[2] = 0;

		cbyte = end[0];
		*top++ = b64string[(int)(cbyte >> 2)];
		obyte = (cbyte << 4) & 0x30;		/* 0011 0000 */

		cbyte = end[1];
		obyte |= (cbyte >> 4);
		*top++ = b64string[(int)obyte];
		obyte = (cbyte << 2) & 0x3C;		/* 0011 1100 */

		if (len) *top++ = b64string[(int)obyte];
		else *top++ = '=';
		*top++ = '=';
	}
	*top = 0;
	return top - to;
}

/* badchar(): check if c is decent; puts either the */
/* location of c or null into p.                  */
#define badchar(c,p) (!(p = memchr(b64string, c, 64)))

long base64_decode (char *const to, const char *const from, const unsigned int len)
{
	const char *fromp = from;
	const char *endp = from+len;
	char *top = to;
	char *p;
	unsigned char cbyte;
	unsigned char obyte;
	int padding = 0;
	int i;

	fromp = from; top = to;
	for (; fromp<endp; ) {
		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else if (cbyte == '%' && fromp[0] == '3' && (fromp[1]&~0x20) == 'D') { cbyte=0; fromp++; fromp++; } /* also = */
		else {
			if (cbyte == '%') {
				if (fromp[0] == '2' && (fromp[1]&~0x20) == 'B') cbyte='+';
				else if (fromp[0]=='2' && (fromp[1]&~0x20) == 'F') cbyte='/';
				else return -1;
				fromp++; fromp++;
			}
			if (badchar(cbyte, p)) return -1;
			cbyte = (p - b64string);
		}
		if (fromp>endp) return -1;
		obyte = cbyte << 2;		/* 1111 1100 */

		if ((cbyte = *fromp++) == '=') cbyte = 0;
		else if (cbyte == '%' && fromp[0] == '3' && (fromp[1]&~0x20) == 'D') { cbyte=0; fromp++; fromp++; } /* also = */
		else {
			if (cbyte == '%') {
				if (fromp[0] == '2' && (fromp[1]&~0x20) == 'B') cbyte='+';
				else if (fromp[0]=='2' && (fromp[1]&~0x20) == 'F') cbyte='/';
				else return -1;
				fromp++; fromp++;
			}
			if (badchar(cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		if (fromp>endp) return -1;
		obyte |= cbyte >> 4;		/* 0000 0011 */
		*top++ = obyte;

		obyte = cbyte << 4;		/* 1111 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else if (cbyte == '%' && fromp[0] == '3' && (fromp[1]&~0x20) == 'D') { cbyte=0; padding++; fromp++; fromp++; } /* also = */
		else {
			if (cbyte == '%') {
				if (fromp[0] == '2' && (fromp[1]&~0x20) == 'B') cbyte='+';
				else if (fromp[0]=='2' && (fromp[1]&~0x20) == 'F') cbyte='/';
				else return -1;
				fromp++; fromp++;
			}
			padding = 0;
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		if (fromp>endp) return -1;
		obyte |= cbyte >> 2;		/* 0000 1111 */
		*top++ = obyte;

		obyte = cbyte << 6;		/* 1100 0000 */
		if ((cbyte = *fromp++) == '=') { cbyte = 0; padding++; }
		else if (cbyte == '%' && fromp[0] == '3' && (fromp[1]&~0x20) == 'D') { cbyte=0; padding++; fromp++; fromp++; } /* also = */
		else {
			if (cbyte == '%') {
				if (fromp[0] == '2' && (fromp[1]&~0x20) == 'B') cbyte='+';
				else if (fromp[0]=='2' && (fromp[1]&~0x20) == 'F') cbyte='/';
				else return -1;
				fromp++; fromp++;
			}
			padding = 0;
			if (badchar (cbyte, p)) return -1;
			cbyte = p - b64string;
		}
		if (fromp>endp) return -1;
		obyte |= cbyte;			/* 0011 1111 */
		*top++ = obyte;
	}

	*top = 0;
	return (top - to) - padding;
}
