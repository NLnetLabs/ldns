#!/usr/bin/perl

# take a numerical range and ranges and 
# only show those ranges or not (-v)
# single numbers: 4
# ranges: 5-10 (inclusive)
# seperated by comma's
# -v reverse

%numbers = ();
$reverse = 0;

foreach $r (@ARGV) {

        if ($r eq "-v") {
                $reverse = 1;
                next;
        }
        
        if ($r =~ /-/) {
                ($s, $e) = split /-/, $r;
                
                if ($s > $e) {
                        next;
                }

                for ($i = $s; $i <= $e; $i++) {
                        $numbers{$i} = 1;
                }
                next;
        }
        $numbers{$r} = 1;
}

# read in the input, pcat style
$i = 1;
LINE: while(<STDIN>) {
        if ($i % 4 == 1) {
                ($left, $right) = split /:/, $_;
                
                if ($reverse == 0) {
                        foreach $k (keys %numbers) {
                                if ($k == $left) {
                                        print $_;
                                        print <STDIN>;
                                        print <STDIN>;
                                        print <STDIN>;
                                        $i++;
                                        next LINE;
                                }
                        }
                        <STDIN>;
                        <STDIN>;
                        <STDIN>;
                } else {
                        foreach $k (keys %numbers) {
                                if ($k == $left) {
                                        <STDIN>;
                                        <STDIN>;
                                        <STDIN>;
                                        $i++;
                                        next LINE;
                                }
                        }
                        print $_;
                        print <STDIN>;
                        print <STDIN>;
                        print <STDIN>;
                }
        }
        $i++;
}
