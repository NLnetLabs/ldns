#!/usr/bin/env bash
# Testbed for projects
# By Wouter Wijngaards, NLnet Labs, 2006.
# BSD License.

# this version prefers gmake if available.
# adds variable LDNS for the LDNS path to use.

REPOSITORY=svn+ssh://open.nlnetlabs.nl/svn/libdns/trunk
DIR=ldns_ttt

# global settings
CONFIGURE_FLAGS=""
PWD=`pwd`
REPORT_FILE="$PWD/testdata/testbed.report"
LOG_FILE=testdata/testbed.log
HOST_FILE=testdata/host_file.$USER

if test ! -f $HOST_FILE; then
	echo "No such file: $HOST_FILE"
	exit 1
fi

function echossh() # like ssh but echos.
{
	echo "ssh $*"
	ssh $*
}

# Compile and run NSD on platforms
function dotest() 
# parameters: <host> <dir>
# host is name of ssh host
# dir is directory of nsd trunk on host
{
	echo "$1 begin on "`date` | /usr/bin/tee -a $REPORT_FILE

	if test $SVN; then
		echossh $1 "cd $2; $SVN up"
	else
		# tar and copy this dir
		echo on
		cd ..
		tar -cf ldns_test.tar .
		scp ldns_test.tar $1:$2
		echossh $1 "cd $2; tar xf ldns_test.tar"
		rm -f ldns_test.tar
	fi
	if test $RUN_TEST = yes; then
	echossh $1 "cd $2/test; $TPKG clean"
	echossh $1 "cd $2/test; bash test_all.sh $TPKG"
	echossh $1 "cd $2/test; $TPKG -q report" | /usr/bin/tee -a $REPORT_FILE
	fi
	echo "$1 end on "`date` | /usr/bin/tee -a $REPORT_FILE
}

echo "on "`date`" by $USER." > $REPORT_FILE
echo "on "`date`" by $USER." > $LOG_FILE

# read host names
declare -a hostname desc dir reconf make libtoolize vars
IFS='	'
i=0
while read a b c d e; do
	if echo $a | grep "^#" >/dev/null; then
		continue # skip it
	fi
	# append after arrays
	hostname[$i]=$a
	desc[$i]=$b
	dir[$i]=$c
	tpkg[$i]=$d
	svn[$i]=$e

	i=$(($i+1))
done <$HOST_FILE
echo "testing on $i hosts"

# do the test
for((i=0; i<${#hostname[*]}; i=$i+1)); do
	if echo ${hostname[$i]} | grep "^#" >/dev/null; then
		continue # skip it
	fi
	 echo "hostname=[${hostname[$i]}]"
	 echo "desc=[${desc[$i]}]"
	 echo "dir=[${dir[$i]}]"
	 echo "tpkg=[${tpkg[$i]}]"
	 echo "svn=[${svn[$i]}]"
 
	RUN_TEST="yes"
	TPKG="${tpkg[$i]}"
	SVN="${svn[$i]}"
	#eval ${vars[$i]}
	echo "*** ${hostname[$i]} ${desc[$i]} ***" | /usr/bin/tee -a $LOG_FILE | /usr/bin/tee -a $REPORT_FILE
	dotest ${hostname[$i]} ${dir[$i]} 2>&1 | /usr/bin/tee -a $LOG_FILE
done

echo "done"
