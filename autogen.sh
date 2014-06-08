#!/bin/sh

srcdir="`dirname $0`"
test -z "$srcdir" && srcdir=.

( cd "$srcdir" && autoreconf -fiv && rm -rf autom4te.cache )
"$srcdir/configure" "$@"
