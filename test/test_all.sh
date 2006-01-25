for tests in *.tpkg
do
	echo "tpkg -a ../.. exe `basename $tests`"
	tpkg -a ../.. exe `basename $tests` 
done 
tpkg report

