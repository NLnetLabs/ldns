#!/usr/bin/env bash
TPKG=/home/jeltejan/repos/tpkg/tpkg

NEED_SPLINT='00-lint.tpkg'
NEED_DOXYGEN='01-doc.tpkg'

cd testdata;
for test in `ls *.tpkg`; do
	SKIP=0
	if echo $NEED_SPLINT | grep $test >/dev/null; then
		if test ! -x "`command -v splint`"; then
			SKIP=1;
		fi
	fi
	if echo $NEED_DOXYGEN | grep $test >/dev/null; then
		if test ! -x "`command -v doxygen`"; then
			SKIP=1;
		fi
	fi
	if test $SKIP -eq 0; then
		echo $test
		$TPKG -a ../.. exe $test
	else
		echo "skip $test"
	fi
done
