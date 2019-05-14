#!/usr/bin/env bash

# do ldns tests
cd test
. common.sh

# find tpkg
if test -x "$(command -v tpkg 2>&1)"; then
	TPKG=tpkg
else
	TPKG="$1"
	if [ -z "$TPKG" ]
	then
	TPKG="$HOME/repos/tpkg/tpkg"
	fi
fi

is_freebsd=$(uname -s 2>&1 | grep -i -c 'freebsd')
test_tool_avail "dig"

echo start the test at "$(date)" in "$(pwd)"
[ "$1" = "clean" ] || [ "$2" = "clean" ] && $TPKG clean
$TPKG -a ../.. fake 01-compile.tpkg

# Works only on FreeBSD really
if [[ "$is_freebsd" -ne 0 ]]; then
    $TPKG -a ../.. fake 02-lint.tpkg
fi

$TPKG -a ../.. fake 07-compile-examples.tpkg
$TPKG -a ../.. fake 16-compile-builddir.tpkg
$TPKG -a ../.. fake 30-load-pyldns.tpkg
$TPKG -a ../.. fake 31-load-pyldnsx.tpkg
$TPKG -a ../.. fake 32-unbound-regression.tpkg
$TPKG -a ../.. fake 999-compile-nossl.tpkg
command -v indent || $TPKG -a ../.. fake codingstyle.tpkg

for tests in *.tpkg
do
	COMMAND="$TPKG -a ../.. exe $(basename "$tests")"
	echo "$COMMAND"
	$COMMAND
done 
echo finished the test at "$(date)" in "$(pwd)"
$TPKG report
cd ..
