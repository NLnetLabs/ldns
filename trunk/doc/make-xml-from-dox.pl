#!/usr/bin/perl

# this perl program takes the html output from
# doxygen and creates and RFC like document
# with the lDNS API. This document also has
# some highlevel language in how to use
# lDNS.

use strict;

# get it from cmd line
my $title = "BOGUS TITLE";

# what to put in front and after
my $func_head = "<t>
<artwork>
";
my $func_foot = "</artwork>
</t>
";
my $list_head = "<t>
<list style=\"symbols\">
";
my $list_foot = "</list>
</t>
";

my $sec_head="<section title=\"$title\">
";
my $sec_foot="</section> <!-- \"$title\">
";

print $sec_head;
print $list_head;
my $indoc = 0;
my @current_func = ();
while (<>) {
	if (/^Function Documentation/) {
		$indoc = 1;
		next;
	}
	if ($indoc == 0) {
		next;
	}
	
	if (/Definition at line/) {
		# we are at the end of the current function 
		print $func_head;
		print @current_func;
		print $func_foot;
		@current_func = ();
		next;
	}
	push @current_func, $_;
}
print $list_foot;
print $sec_foot;
