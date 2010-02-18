#!/bin/sh
BASE=$(dirname "$0")
cd $BASE/..
./configure \
      --prefix=/usr \
      --sysconfdir=/etc \
      --libexecdir=/usr/lib \
      --localstatedir=/var \
      --datadir=/usr/share \
      --mandir=/usr/share/man \
      --infodir=/usr/share/info \
  --without-log --disable-daemon --with-ssl --disable-log
