#!/bin/bash
# do ldns tests
cd test
. common.sh

# find tpkg
if test -x "`which tpkg 2>&1`"; then
	TPKG=tpkg
else
	TPKG=$1
	if [ -z "$TPKG" ]
	then
	TPKG=$HOME/repos/tpkg/tpkg
	fi
fi

test_tool_avail "dig"

echo start the test at `date` in `pwd`
[ "$1" = "clean" -o "$2" = "clean" ] && $TPKG clean
$TPKG -a ../.. fake 01-compile.tpkg
$TPKG -a ../.. fake 02-lint.tpkg		# Works only on FreeBSD really
$TPKG -a ../.. fake 07-compile-examples.tpkg
$TPKG -a ../.. fake 16-compile-builddir.tpkg
$TPKG -a ../.. fake 30-load-pyldns.tpkg
$TPKG -a ../.. fake 31-load-pyldnsx.tpkg
$TPKG -a ../.. fake 32-unbound-regression.tpkg
$TPKG -a ../.. fake 999-compile-nossl.tpkg
which indent || $TPKG -a ../.. fake codingstyle.tpkg

for tests in *.tpkg
do
	COMMAND="$TPKG -a ../.. exe `basename $tests`"
	echo $COMMAND
	$COMMAND
done 
echo finished the test at `date` in `pwd`
$TPKG report
cd ..

