#!/usr/bin/perl

# this perl program takes the html output from
# doxygen and creates and RFC like document
# with the lDNS API. This document also has
# some highlevel language in how to use
# lDNS.

use strict;

# what to put in front and after
my $func_head = "<t>
<artwork>
";
my $func_foot = "</artwork>
</t>
";

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

