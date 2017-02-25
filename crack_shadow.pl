#!/usr/bin/env perl
use strict;
use warnings;

use feature 'say';

use Data::Dumper;



=pod

crack_shadow.pl

used to crack shadow hashes created by crypt

=cut



my $hash = shift // die "usage: $0 <shadow hash> <text file> [lines to skip]";
die "invalid hash '$hash'" unless $hash =~ /\A(\$.*)\$[0-9a-zA-Z\.\/]+\Z/s;
my $salt = $1;

open my $fil, '<', shift // die 'text file required to hash against';

my $skip = shift // 0;

<$fil> foreach 1 .. $skip;

my $count = $skip;
while (<$fil>) {
	y/\r\n//d;
	if (crypt($_, $salt) eq $hash) {
		say "found: '$_' => '$hash'";
		last;
	}
	print "$count\n" unless ++$count % 100;
}
