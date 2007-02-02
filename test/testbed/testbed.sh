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
REPORT_FILE=testdata/testbed.report
LOG_FILE=testdata/testbed.log
HOST_FILE=testdata/host_file.$USER

if test ! -f $HOST_FILE; then
	echo "No such file: $HOST_FILE"
	exit 1
fi

function echossh() # like ssh but echos.
{
	echo "> ssh $*"
	ssh $*
}

# Compile and run NSD on platforms
function dotest() 
# parameters: <host> <dir>
# host is name of ssh host
# dir is directory of nsd trunk on host
{
	echo "$1 begin on "`date` | tee -a $REPORT_FILE

	if test $SVN = yes; then
		echossh $1 "cd $2; svn up"
		echossh $1 "cd $2; if test ! -f configure -o configure.ac -nt configure; then $AC_CMD; fi"
	else
		# svn and autoconf locally
		echo "fake svn via svnexport, tar, autoconf, bison, flex."
		svn export $REPOSITORY $DIR
		(cd $DIR; $AC_CMD; rm -r autom4te* .c-mode-rc.el .cvsignore)
		if test "need_fixup_flexbison" = "yes"; then
			(cd unbound_ttt; \
			echo "#include <config.h>" > zlexer.c ; \
			flex -i -t zlexer.lex >> zlexer.c ; \
			bison -y -d -o zparser.c zparser.y ; \
			echo "#include \"configyyrename.h\"" > configlexer.c ; \
			flex -i -t configlexer.lex >> configlexer.c ; \
			bison -y -d -o configparser.c configparser.y )
		fi
		if test $FIXCONFIGURE = yes; then
			echo fixing up configure length test.
			(cd unbound_ttt; mv configure oldconf; sed -e 's?while (test "X"?lt_cv_sys_max_cmd_len=65500; echo skip || while (test "X"?' <oldconf >configure; chmod +x ./configure)
		fi
		du $DIR
		rsync -vrcpz --rsync-path=/home/wouter/bin/rsync $DIR $1:$DIR
		# tar czf unbound_ttt.tgz unbound_ttt
		rm -rf $DIR
		# ls -al unbound_ttt.tgz
		# scp unbound_ttt.tgz $1:unbound_ttt.tar.gz
		# rm unbound_ttt.tgz
		# echossh $1 "gtar xzf unbound_ttt.tar.gz && rm unbound_ttt.tar.gz"
	fi
	DISABLE=""
	if test $IP6 = no; then
		DISABLE="--disable-ipv6"
	fi
#	if test x$LDNS != x; then
#		DISABLE="--with-ldns=$LDNS $DISABLE"
#	fi
	echossh $1 "cd $2; if test ! -f config.h -o configure -nt config.h; then ./configure $CONFIGURE_FLAGS $DISABLE; fi"
	echossh $1 "cd $2; if test -f "'"`which gmake`"'"; then gmake; else $MAKE_CMD; fi"
	echossh $1 "cd $2; if test -f "'"`which gmake`"'"; then gmake doc; else $MAKE_CMD doc; fi"
	if test $RUN_TEST = yes; then
	echossh $1 "cd $2/test; $TPKG clean"
	echossh $1 "cd $2/test; bash test_all.sh $TPKG"
	echossh $1 "cd $2/test; $TPKG -q report" | tee -a $REPORT_FILE
	fi
	echo "$1 end on "`date` | tee -a $REPORT_FILE
}

echo "on "`date`" by $USER." > $REPORT_FILE
echo "on "`date`" by $USER." > $LOG_FILE

# read host names
declare -a hostname desc dir reconf make libtoolize vars
IFS='	'
i=0
while read a b c d e f g h; do
	if echo $a | grep "^#" >/dev/null; then
		continue # skip it
	fi
	# append after arrays
	hostname[$i]=$a
	desc[$i]=$b
	dir[$i]=$c
	reconf[$i]=$d
	make[$i]=$e
	libtoolize[$i]=$f
	vars[$i]=$g
	tpkg[$i]=$h

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
	 echo "reconf=[${reconf[$i]}]"
	 echo "make=[${make[$i]}]"
	 echo "libtoolize=[${libtoolize[$i]}]"
	 echo "vars=[${vars[$i]}]"
	 echo "tpkg=[${tpkg[$i]}]"
 
	AC_CMD="${libtoolize[$i]}; ${reconf[$i]}"
	MAKE_CMD="${make[$i]}"
	SVN=yes
	IP6=yes
	FIXCONFIGURE=no
	RUN_TEST=yes
	LDNS=
	TPKG="${tpkg[$i]}"
echo "AC: $AC_CMD"
	eval ${vars[$i]}
	echo "*** ${hostname[$i]} ${desc[$i]} ***" | tee -a $LOG_FILE | tee -a $REPORT_FILE
	dotest ${hostname[$i]} ${dir[$i]} 2>&1 | tee -a $LOG_FILE
done

echo "done"
