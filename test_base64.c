#include <stdio.h>
#include <string.h>
#include "base64.h"

char *from = "J65eohMg3gN%2byIbmR5H%2fLjphNGZkYmQ5ZS1jYTgxLTQ1OWItOWQ3Ny0xMjNmYThhMWU2MzA%3D";
char to[1024];

int main() {
  printf("%s %d\n",from,strlen(from));
  int outlen = base64_decode(to, from, strlen(from));
  printf("%s %d\n", to, outlen);
  return 0;
}
