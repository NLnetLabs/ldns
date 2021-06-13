#!/usr/bin/env bash

BUILD_DIR=$(pwd)
echo "PATH=$PATH" > "$BUILD_DIR/test/.tpkg.var.master"

if git log HEAD^..HEAD | grep -q 'git:TEST [0-9][0-9]*'
then
	ONLY_TEST=$(git log HEAD^..HEAD | grep 'git:TEST [0-9][0-9]*' | sed 's/^.*git:TEST \([0-9][0-9]*\).*$/\1/g')
else
	ONLY_TEST=""
fi

if git log HEAD^..HEAD | grep -q 'git:REGRESSION'
then
	NO_REGRESSION=0
else
        NO_REGRESSION=1
fi

if [ -z "$TPKG" ] || [ ! -x "$TPKG" ]
then
        if [ -x tpkg/tpkg ]		; then TPKG="$(pwd)/tpkg/tpkg"
        elif [ -x test/tpkg/tpkg ]	; then TPKG="$(pwd)/test/tpkg/tpkg"
        elif command -v tpkg > /dev/null; then TPKG="$(command -v tpkg)"
        else
                echo Did not find tpkg program!
                exit 255    # Shell can only return 0-255
        fi
fi

# RUN THE TESTS
for tests in "$BUILD_DIR"/test/*.tpkg
do
	TESTFN="$(basename "$tests")"
	TESTNR=${TESTFN%-*}
	[ -n "$ONLY_TEST" ] && [ x"$ONLY_TEST" != x"$TESTNR" ] && continue
	case "$TESTNR" in
	[3-5][0-9]*)	[ $NO_REGRESSION = 1 ] && continue
			;;
	esac
	case $TESTNR in
	02)	# splint doesn't work on linux
		[ "x$(uname -s)" = "xLinux" ] && continue
		;;
	32)	# No backwards compatibility regression testing 
		# when .so had major version bump.
		chmod +x "$BUILD_DIR/packaging/ldns-config"
		BINAPI=$("$BUILD_DIR/packaging/ldns-config" --libversion)
		[ "x${BINAPI#*.}" = "x0.0" ] && continue
	esac
	$TPKG -b "$BUILD_DIR/test" -a "$BUILD_DIR" exe "$TESTFN"
done

cd test || { echo "Where is the test directory?"; exit 1; }
exec $TPKG -n -1 r
