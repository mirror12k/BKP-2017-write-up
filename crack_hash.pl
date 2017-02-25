#!/usr/bin/env perl
use strict;
use warnings;

use feature 'say';

use Digest::MD5 qw/ md5_hex /;
use Digest::SHA qw/  sha1_hex sha256_hex sha384_hex sha512_hex /;
use Digest::SHA3 qw/ sha3_224_hex sha3_256_hex sha3_384_hex sha3_512_hex /;

use Data::Dumper;



=pod

crack_hash.pl

used to crack simple hashes of basic hash functions.
has an optional argument to skip a number of lines from the text file.

=cut



my %hash_functions = (
	md5 => \&md5_hex,

	sha1 => \&sha1_hex,

	sha256 => \&sha256_hex,
	sha384 => \&sha384_hex,
	sha512 => \&sha512_hex,

	sha3_224 => \&sha3_224_hex,
	sha3_256 => \&sha3_256_hex,
	sha3_384 => \&sha3_384_hex,
	sha3_512 => \&sha3_512_hex,
);

my $fun = shift // die "usage: $0 <hash function> <hash> <text file> [lines to skip]";
$fun = $hash_functions{$fun} // die "unknown hash function name '$fun', available functions are: " . Dumper [ sort keys %hash_functions ];

my $hash = shift // die "hash required";
die "invalid hash" unless $hash =~ /\A[0-9a-f]+\Z/;

open my $fil, '<', shift // die 'text file required to hash against';


my $skip = shift // 0;

<$fil> foreach 1 .. $skip;

my $count = $skip;
while (<$fil>) {
	y/\r\n//d;
	if ($fun->($_) eq $hash) {
		say "found: '$_' => '$hash'";
		last;
	}
	print "$count\n" unless ++$count % 100000;
}
