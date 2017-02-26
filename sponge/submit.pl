#!/usr/bin/env perl
use strict;
use warnings;

use feature 'say';

use LWP::UserAgent;



my $solution = shift // die 'solution argument required';


my $ua = LWP::UserAgent->new;
my $res = $ua->get("http://54.202.194.91:12345/$solution");

say 'status: ', $res->status_line;
say $res->decoded_content;



