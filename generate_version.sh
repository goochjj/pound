#!/bin/sh
#
# An example hook script that is called after a successful
# commit is made.
#
# To enable this hook, rename this file to "post-commit".

#: Nothing
pwd
git describe --tags --long | sed -e 's,^\(upstream/\|\)\(.*\)$,char *POUND_VERSION = "\2";,' > version.c
git checkout debian/changelog
(
  DV=`git describe --tags --long |sed -e 's,^\(upstream/\|\)v\([0-9]*\.[0-9]*\)\.[0-9]*-\([0-9]*\).*,\2-\3,'`
  echo "sapphire-pound25 ($DV) unstable; urgency=high"
  echo ""
  echo "  * Update package version number to source control"
  echo ""
  echo " -- Joseph Gooch <mrwizard@k12system.com>  "$(date -R)
  echo ""
  cat debian/changelog
) > hi && mv -f hi debian/changelog
