
str2host.xml: html/str2host_8c.html 
	links -dump html/str2host_8c.html | ./make-xml-from-dox.pl > str2host.xml

API2.xml: str2host.xml API-header.xml API-footer.xml
	cat API-header.xml str2host.xml API-footer.xml > API2.xml
	xml2rfc API2.xml

clean:
	rm -f *.txt
	rm -f str2host.xml
	rm -f API2.xml

