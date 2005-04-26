all:	function_manpages
	 cat ../ldns/*.h | ./doxyparse.pl -m function_manpages	

clean:
	rm -f *.txt
	rm -f *.html
	rm -rf html
	rm -rf man
	rm -rf latex
