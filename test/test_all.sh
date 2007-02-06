TPKG=$1
if [ -z "$ARG" ]
then
  TPKG=$HOME/repos/tpkg/tpkg
fi


for tests in *.tpkg
do
	echo "$TPKG -a ../.. exe `basename $tests`"
	$TPKG -a ../.. exe `basename $tests` 
done 
tpkg report

