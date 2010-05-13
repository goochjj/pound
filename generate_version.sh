#!/bin/sh
#
# An example hook script that is called after a successful
# commit is made.
#
# To enable this hook, rename this file to "post-commit".

#: Nothing
pwd
git describe --tags --long | sed -e 's,^\(.*\)$,char *POUND_VERSION = "\1";,' > version.c

