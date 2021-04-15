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
my @paddingbytes = (
	# random bytes / aligned with C code
	0xc5, 0xf7, 0x40, 0xd8, 0x1f, 0xda, 0x49, 0xb6,
	0xe6, 0x1b, 0x5c, 0xee, 0xbd, 0x29, 0xbb, 0xa5,
	0x89, 0x99, 0x93, 0x8f, 0x4b, 0x8b, 0xca, 0x40,
	0xbb, 0x5a, 0xb4, 0x05, 0x1b, 0x9a, 0xe7, 0x4d
);
my $paddingstr = pack("C*", @paddingbytes);
my $pwin  = $password.substr($paddingstr, length($password));
my $hash1 = md5($pwin);
my $hash2 = md5($hash1);
my $toxor = $hash1.substr($hash2, 0, $MAXKEYLENGTH - 16);

my @chars = unpack("C*", substr($toxor, 0, 1));
print "/* ".$chars[0]." */\n";

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
