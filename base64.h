#ifndef INC_BASE64_H
#define INC_BASE64_H

extern long base64_encode(char *to, char *from, unsigned int len);
extern long base64_decode(char *to, char *from, unsigned int len);

#endif
