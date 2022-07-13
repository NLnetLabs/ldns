#!/usr/bin/env bash

# do ldns tests
cd test || { echo "Must be executed from srcdir"; exit -1; }
. common.sh

# find tpkg
if [ -z "$TPKG" ] || [ ! -x "$TPKG" ]
then
        if [ -x tpkg/tpkg ]		; then TPKG="$(pwd)/tpkg/tpkg"
        elif [ -x test/tpkg/tpkg ]	; then TPKG="$(pwd)/test/tpkg/tpkg"
        elif command -v tpkg > /dev/null; then TPKG="$(command -v tpkg)"
        else
		TPKG=$1
		if [ -z "$TPKG" ]
		then
			TPKG=$HOME/repos/tpkg/tpkg
                	echo Did not find tpkg program!
                	exit -1
		fi
        fi
fi

is_freebsd=$(uname -s 2>&1 | grep -i -c 'freebsd')
test_tool_avail "dig"

echo start the test at "$(date)" in "$(pwd)"
[ "$1" = "clean" ] || [ "$2" = "clean" ] && $TPKG clean
$TPKG -a ../.. fake 01-compile.tpkg

# Works only on FreeBSD really
if [[ "$is_freebsd" -eq 0 ]]; then
    $TPKG -a ../.. fake 02-lint.tpkg
fi

$TPKG -a ../.. fake 07-compile-examples.tpkg
$TPKG -a ../.. fake 16-compile-builddir.tpkg
$TPKG -a ../.. fake 30-load-pyldns.tpkg
$TPKG -a ../.. fake 31-load-pyldnsx.tpkg
$TPKG -a ../.. fake 32-unbound-regression.tpkg
$TPKG -a ../.. fake 999-compile-nossl.tpkg
command -v indent || $TPKG -a ../.. fake codingstyle.tpkg
grep -q '^#define HAVE_SSL ' ../ldns/config.h || (
	$TPKG -a ../.. fake 19-keygen.tpkg
	$TPKG -a ../.. fake 20-sign-zone.tpkg
	$TPKG -a ../.. fake 25-ZONEMD.tpkg
)

failed=0
for tests in *.tpkg
do
	COMMAND="$TPKG -a ../.. exe $(basename "$tests")"
	echo "$COMMAND"
	$COMMAND
	if [ $? -ne 0 ]; then ((failed=failed+1)); fi
done 
echo finished the test at "$(date)" in "$(pwd)"
$TPKG report
cd ..

exit $failed
