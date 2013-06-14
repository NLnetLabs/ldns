#!/bin/sh

BUILD_DIR=`pwd`
echo "PATH=$PATH" > $BUILD_DIR/test/.tpkg.var.master

if git log HEAD^..HEAD | grep -q 'git:TEST [0-9][0-9]*'
then
	ONLY_TEST=`( cd $BUILD_DIR ; git log HEAD^..HEAD ) | grep 'git:TEST [0-9][0-9]*' | sed 's/^.*git:TEST \([0-9][0-9]*\).*$/\1/g'`
else
	ONLY_TEST=""
fi

if git log HEAD^..HEAD | grep -q 'git:NO REGRESSION'
then
	NO_REGRESSION=1
else
        NO_REGRESSION=0
fi

# RUN THE TESTS
for tests in $BUILD_DIR/test/*.tpkg 
do
	TESTFN=`basename $tests`
	TESTNR=`echo $TESTFN | sed 's/-.*$//g'`
	if [ ! -z "$ONLY_TEST" ]
	then
		if [ x$ONLY_TEST != x$TESTNR ]
		then
			continue
		fi
	fi
	if [ $NO_REGRESSION = 1 -a $TESTNR -ge 30 ]
	then
		continue
	fi
	tpkg -b $BUILD_DIR/test -a $BUILD_DIR exe $TESTFN
done
# END

