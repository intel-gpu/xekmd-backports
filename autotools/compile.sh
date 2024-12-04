#!/bin/sh

# Limit nproc value to be not more than 64 to avoid build machine hangs
NP=`nproc`
NPC=$(( $NP > 64 ? 64 : $NP-1 ))

HEADERS="/lib/modules/`uname -r`/build"

if [ ! -z "$1" ]
then
	HEADERS="$1"
fi

echo "Using Headers from folder $HEADERS"

echo "Running Autotools"
autoreconf --install;
autoconf
autoheader
automake --add-missing
./configure --enable-linux-builtin --with-linux=$HEADERS

echo "Starting Compilation"
cp src/defconfigs/xe src/.config
make olddefconfig
make -j$NPC modules

echo "Done"
