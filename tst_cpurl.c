#include <stdio.h>
#include "pound.h"

// Make svc.c happy
int         alive_to,           /* check interval for resurrection */
            daemonize,          /* run as daemon */
            log_facility,       /* log facility to use */
            print_log,          /* print log messages to stdout/stderr */
            grace,              /* grace period before shutdown */
            control_sock;       /* control socket */

SERVICE     *services;          /* global services (if any) */

LISTENER    *listeners;         /* all available listeners */

regex_t HEADER,             /* Allowed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN,           /* responses for which we ignore content */
        LOCATION,           /* the host we are redirected to */
        AUTHORIZATION;      /* the Authorisation header */

static int runTest(char * src, char * expected) {
  char buf[1024];

  cpURL(buf, src, strlen(src));
  if (strcmp(buf, expected)) {
    fprintf(stderr, "Gave:\t\t%s\ngot:\t\t%s\nexpected:\t%s\n\n", src, buf, expected);
    return 0;
  }
  printf("%s passed\n", src);
  return 1;
}

static int runTestNulls(char * src, char * expected, int expLen) {
  char buf[1024];

  cpURL(buf, src, strlen(src));
  if (memcmp(buf, expected, expLen)) {
    fprintf(stderr, "Gave:\t\t%s\ngot:\t\t%s\nexpected:\t%s\n\n", src, buf, expected);
    return 0;
  }
  printf("%s passed\n", src);
  return 1;
}

int main() {
  char buf1[1024], buf2[1024];
  char *p1,*p2;
  unsigned int i;
  int err = 0;

  if (!runTest("This is a test.", "This is a test.")) err++;
  if (!runTest("This is %% another test", "This is %% another test")) err++;
  if (!runTest(
    "This%24%26%2B%2C%2F%3A%3B%3D%3F%40%20%22%3C%3E%23%25%7B%7D%7C%5C%5E%7E%5B%5D%60testing%2b%2c%2f%3a%3b%3d%3f%3c%3e%7b%7d%7c%5c%5e%7e%5b%5d%5%0%%%z%x%%x%%",
    "This$&+,/:;=?@ \"<>#%{}|\\^~[]`testing+,/:;=?<>{}|\\^~[]%5%0%%%z%x%%x%%")) err++;

  if (!runTest(
    "%5b%5d%5%0%%%z%x%%x%%",
    "[]%5%0%%%z%x%%x%%")) err++;

  if (!runTest("%%20", "%%20")) err++;
  if (!runTest("%", "%")) err++;
  if (!runTest("%0", "%0")) err++;

  p1=buf1; p2=buf2;
  for(i=1; i<=255; i++) {
    *p1++ = '%';
    *p1++ = (i>>4)>9?(i>>4)+'A'-10:(i>>4)+'0';
    *p1++ = (i&0x0F)>9?(i&0x0f)+'A'-10:(i&0x0f)+'0';
    *p2++ = (char)i;
  }
  *p1++ = 0;
  *p2++ = 0;
  if (!runTest(buf1,buf2)) err++;

  p1=buf1; p2=buf2;
  for(i=1; i<=255; i++) {
    *p1++ = '%';
    *p1++ = (i>>4)>9?(i>>4)+'a'-10:(i>>4)+'0';
    *p1++ = (i&0x0F)>9?(i&0x0f)+'a'-10:(i&0x0f)+'0';
    *p2++ = (char)i;
  }
  *p1++ = 0;
  *p2++ = 0;
  if (!runTest(buf1,buf2)) err++;

  if (!runTestNulls("This has a %00 null in the middle", "This has a \000 null in the middle", strlen("This has a %00 null in the middle")-2)) err++;
  exit(err);
}
