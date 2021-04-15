#!/usr/bin/perl
# Ma_Sys.ma TRTOTP Script to convert keys to header include file 1.0.0,
# Copyright (c) 2021 Ma_Sys.ma.
# For further info send an e-mail to Ma_Sys.ma@web.de

use strict;
use warnings FATAL => 'all';
use autodie;

use Digest::MD5 qw(md5);      # standard
require Config::INI::Reader;  # DEPENDS libconfig-ini-perl
require MIME::Base32;         # DEPENDS libmime-base32-perl

# use Data::Dumper;           # DEBUG ONLY

if($#ARGV < 0 or $ARGV[0] eq "--help") {
	print "USAGE $0 secrets.ini > keys.inc\n";
	exit(1);
}

my $ini = Config::INI::Reader->read_file($ARGV[0]);
my $password = $ini->{global}->{password};
delete $ini->{global};

# Currently hard-coded length of 20. See C code for the implementation that
# can do an arbitrary width.
my $MAXKEYLENGTH = 20;
my $hash1 = md5($password);
my $hash2 = md5($hash1);
my $toxor = $hash1.substr($hash2, 0, $MAXKEYLENGTH - 16);

for my $entry (sort keys %{$ini}) {
	my $decoded = MIME::Base32::decode_base32($ini->{$entry}->{key});
	my $encrypted = $toxor ^ $decoded;
	# https://stackoverflow.com/questions/13158976/split-binary-data-into-
	my @bytes = unpack "C*", $encrypted;
	# -> trtotp.c
	# struct db_entry {
	# 	unsigned char name[16]; /* max 15 chars + trailing '0' */
	# 	unsigned char type;
	# 	unsigned char keylen;
	# 	unsigned char timestep;
	# 	unsigned char digits;
	# 	unsigned char key[MAXKEYLENGTH]; /* encrypted */
	# };
	print "{\"$entry\", 0, ".length($decoded).", ".
		$ini->{$entry}->{timestep}.", ".
		$ini->{$entry}->{digits}.", {".
		join(",", map { sprintf("0x%02x", $_); } @bytes)."},},\n";
}
