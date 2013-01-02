#!/usr/bin/env perl
use warnings;
use strict;
#use re "debugcolor";

# converter for strace dirent.h files

# tested with strace 1f21513c38cbcb1d3d16e7b8ac0f17ef4793085e
# works on all files, but e.g. in mips are abi specific ifdefs which must
# be cleaned up manually before converting.

my $longestname = 0;
my $total = 0;
my $scs = 0;

my $stringtbl = "\n";

print "static const syscalldef syscalldefs[] = {\n";

while(<>) {
	#        {    0    ,    TN|BZ|0    ,   abcde_fg ,    "foo_bar"  (,)        },      / *    123 */
	if(    /\{\s*(\w+)\,\s*([\w\|\s]+)\,\s*([\w_]+)\,\s*\"([\w_:]+)\"\,{0,1}\s*\}\,\s*\/\*\s*(\d+)\,*\s*(not implemented ){0,1}(\?\?\? ){0,1}\*\/\s*/) {
		my $argcount = $1;
		my $flags = $2;
		my $foo = $3;
		my $sc_str = $4;
		my $num = $5;
		$argcount = 6 if $argcount eq "MA";
		#print("\t[SYSCALL_OR_NUM($num, SYS_$sc_str)]\t = { .argcount = $argcount, .flags = $flags, .name = \"$sc_str\" },\n");
		#printf "\t[SYSCALL_OR_NUM($num, SYS_$sc_str)]\t = { .argcount = $argcount, .nameoffset = %d },\n", length($stringtbl);
		printf "\t[SYSCALL_OR_NUM($num, SYS_$sc_str)]\t = MAKE_UINT16($argcount, %d),\n", length($stringtbl);
		
		$stringtbl .= $sc_str . "\n";
		$longestname = length($sc_str) if(length($sc_str) > $longestname);
		$total += length($sc_str) + 1;
		$scs++;
	} else {
		print "// XXXXXXX $_";
	}
}

print "};\n\n";

$stringtbl =~ s/\n/\\0\"\n\"/g;

print "static const char syscallnames[] = \"$stringtbl\";\n";

print("/*\n");
print("longest string: $longestname\n");
print("total concatenated string length: $total\n");
printf("pointer overhead: %d\n", $scs * 8);
printf("strings + overhead: %d\n", ($scs * 8) + $total);
printf("total size aligned to max strlen %d\n", ($longestname + 1) * $scs);
print("*/\n");