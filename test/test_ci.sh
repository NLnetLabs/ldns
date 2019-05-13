#!/bin/sh

BUILD_DIR=`pwd`
echo "PATH=$PATH" > $BUILD_DIR/test/.tpkg.var.master

if git log HEAD^..HEAD | grep -q 'git:TEST [0-9][0-9]*'
then
	ONLY_TEST=`( cd $BUILD_DIR ; git log HEAD^..HEAD ) | grep 'git:TEST [0-9][0-9]*' | sed 's/^.*git:TEST \([0-9][0-9]*\).*$/\1/g'`
else
	ONLY_TEST=""
fi

if git log HEAD^..HEAD | grep -q 'git:REGRESSION'
then
	NO_REGRESSION=0
else
        NO_REGRESSION=1
fi

if [ -z "$TPKG" -o ! -x "$TPKG" ]
then
        if which tpkg > /dev/null	; then TPKG=`command -v tpkg`
        elif [ -x $HOME/bin/tpkg ]	; then TPKG=$HOME/bin/tpkg
        elif [ -x $HOME/local/bin/tpkg ]; then TPKG=$HOME/local/bin/tpkg
        elif [ -x /home/tpkg/bin/tpkg ]	; then TPKG=/home/tpkg/bin/tpkg
        elif [ -x ../tpkg/tpkg ]	; then TPKG=../tpkg/tpkg
        else
                echo Did not find tpkg program!
                exit -1
        fi
fi
# RUN THE TESTS
for tests in $BUILD_DIR/test/*.tpkg 
do
	TESTFN=`basename $tests`
	TESTNR=`echo $TESTFN | sed 's/-.*$//g'`
	[ ! -z "$ONLY_TEST" -a x$ONLY_TEST != x$TESTNR ] && continue
	case $TESTNR in
	[3-5][0-9]*)	[ $NO_REGRESSION = 1 ] && continue
			;;
	esac
	case $TESTNR in
	02)	# splint doesn't work on linux
		[ "x`uname -o`" = "xGNU/Linux" ] && continue
		;;
	32)	# No backwards compatibility regression testing 
		# when .so had major version bumb.
		chmod +x $BUILD_DIR/packaging/ldns-config
		BINAPI=`$BUILD_DIR/packaging/ldns-config --libversion`
		[ "x${BINAPI#*.}" = "x0.0" ] && continue
	esac
	$TPKG -b $BUILD_DIR/test -a $BUILD_DIR exe $TESTFN
done

# -----------------------------------------------------------------------------
# ----  Testing part
#
( cd test; $TPKG -q -n `ls result.*|wc -l` report >/dev/null )

# -----------------------------------------------------------------------------
# ----  Reusable reporting part
#
if test "$?" -eq "0"; then STATUS="pass"; else STATUS="FAIL"; fi
CI_ID=2

REPOS=$(basename $(pwd))
REPOS=${REPOS%.git}
CI_URI="${CI_PROJECT_URL}/builds/${CI_BUILD_ID}"
while [ $# -ge 1 ]
do
	echo "Sending mail to $1... ($# >= 1)"
	(
		git log -1 --format="From %H %ad%nFrom: %an <%ae>"
		BRANCH=$(
			for W in $( git log -1 --format=%d | tr "()," "   " )
			do echo $W
			done | grep -v HEAD | head -1
			)
		BRANCH="${BRANCH#origin/}"
		echo "X-Git-Refname: $BRANCH"
		if [ -z "$BRANCH" -o "$BRANCH" = "master" ]
		then
			BRANCH=""
		else
			BRANCH="/$BRANCH"
		fi
		git log -1 --format="Subject: [git: $REPOS$BRANCH][$STATUS] %s"
		echo "To: $1"
		echo "Date: `LC_ALL=C date '+%a, %e %b %Y %T %z (%Z)'`"
		echo "X-Git-Repository: $REPOS"
		git log -2 --format="X-Git-Oldrev: %H"
		git log -1 --format="X-Git-Newrev: %H"
		echo
		uname -a
		echo
		echo "$CI_URI"
		echo

		# -------------------------------------------------------------
		# ----  Repository specific reporting part
		# ----
			( cd test; $TPKG report )
		# ----
		# -------------------------------------------------------------


	) | sendmail $1
	shift
done
test "$STATUS" = "pass"
