TPKG=$1
if [ -z "$TPKG" ]
then
  TPKG=$HOME/repos/tpkg/tpkg
fi


for tests in *.tpkg
do
	COMMAND="$TPKG -a ../.. exe `basename $tests`"
	echo $COMMAND
	$COMMAND
	if [ $? = 1 ]; then
		if [ $tests = "01-compile.tpkg" ]; then
			echo "Important base test failed, stopping."
			$TPKG report
			exit 1
		fi
	fi
done 
$TPKG report

