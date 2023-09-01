---
section: 32
x-masysma-name: ti84plus/z80/trtotp
title: TOTP Program for TI-84+ Calculators
date: 2021/04/15 18:43:42
lang: en-US
author: ["Linux-Fan, Ma_Sys.ma (Ma_Sys.ma@web.de)"]
keywords: ["ti", "calculator", "totp", "crypto", "z80"]
x-masysma-version: 1.0.1
x-masysma-website: https://masysma.net/32/ti84plus_z80_trtotp.xhtml
x-masysma-repository: https://www.github.com/m7a/bo-z80-ti84plus-trtotp
x-masysma-copyright: |
  Copyright (c) 2021 Ma_Sys.ma.
  For further info send an e-mail to Ma_Sys.ma@web.de.
---
Description
===========

This repository contains a proof-of-concept application demonstrating the
feasability of running a TOTP authenticator application on a Texas Instruments
TI-84+ programmable calculator.

![Animation showing the basic usage](ti84plus_z80_trtotp_att/animdescr.gif)

This implementation supports multiple (12 seems to be the maximum) TOTP seeds
and allows them to be selected through an interactive menu displayed on the
calculator. In terms of algorithms, _only_ TOTP using a HMAC-SHA-1 is supported.

WARNING: Depending on what other applications you want to load on the
calculator, the number of TOTP tokens supported can be much smaller. You can
notice out of memory conditions by the calculator displaying `ERR:INVALID` upon
trying to start the program or spontaneously resetting after terminating the
application.

Security Considerations
=======================

WARNING: This program was created as a learning exercise. It does not establish
the security properties provided by actual hardware tokens and any smartphone
outperforms the program presented here. Use responsibly and AT YOUR OWN RISK!

In fact, it seems near impossible to securely process TOTP on the calculator.
This mostly stems from two unfortunate facts:

 1. Memory on the calculator is not protected.
 2. There are not enough ressources to process modern crypto like AES or
    PBKDEF2.

This proof of concept application proposes a sort of “might work” solution for
the second problem while leaving the first problem unresolved.

TOTP seeds are worth protecting while stored at rest. A usual modern approach
to protect them with a password could be as follows: Use a password based key
derivation function to derive an encryption key and then use a strong
cryptographic primitive like AES-GCM to encrypt the data. This approach does not
seem viable to run on the calculator for the following reasons:

 * The algorithms (AES, GCM, PBKDEF2) would all need to be implemented for the
   calculator making the program much larger. Program size is a real issue and
   while developing the solution presented here the limits were exceeded
   multiple times. This is never indicated clearly but rather surfaces when
   the calculator spontaneously turns off or just says `ERR:INVALID` upon trying
   to open the program.

 * Password based key derivation functions make cracking the passwords difficult
   by iterating a hash (or similar) function. Problem is: The calculator's
   abilities to iterate hash functions are tightly limited by its slow
   processor. Hence it is to be expected that any reasonable computation time
   (say: 5 sec) on the calculator would consist of too few iterations to pose
   any significant challenge to an adversary.

From this, one could conclude that securing anything with encryption on the
calculator is futile.

Here is an idea how one might go about it: It is not possible to prevent an
adversary from cracking the password, but how would they notice that the found
password is indeed, correct? In fact, if nothing is known about the plaintext,
then an adversary might not be able to find the secret despite having the
ability to compute all possible decryptions. My idea of how this might be
achieved is: _Encrypt only the TOTP seeds_. A TOTP seed can be any byte sequence
and hence, the adversary cannot tell if a given TOTP sequence is correct.

Note that this assumption is quite strong (even impracticably so) because any
bystander observing just a single correct TOTP code gains the additional
knowledge needed to verify the correctness of the associated TOTP seed and can
thus decrypt the data completely. Therein lies the weakness of this approach!

But following the assumption that the adversary knows nothing about the TOTP
seed of interest, and given that all TOTP seeds are expected to be unique, it
becomes possible to encrypt them using an one-time-pad. Again, there is need to
generate the one time pad key from a password, but given the additional
assumptions, one can use even very fast hash functions because it is no longer
necessary to protect from brute-force attacks against the password: Using
brute-force, an adversary _will_ arrive at the correct password but without
additional information about the TOTP's correctness, it will not be possible to
tell which of the tried passwords was the correct one.

The program presented here implements the generation of the one time pad from
the user's password as follows:

	first 16 bytes of OTP key = md5(password || salt)
	next  16 bytes of OTP key = md5(previous 16 bytes of OTP key)

This is as insecure as it gets, but it is (1) fast enough to process on the
calculator and (2) probably secure enough to drive off a script kiddie having
obtained just the encrypted TOTP seeds.

Dependencies
============

The following are needed to compile and use this tool:

 * [sdcc(1)](https://manpages.debian.org/buster/sdcc/sdcc.1.en.html) --
   Small Device C Compiler along with the included
   [sdasz80(1)](https://manpages.debian.org/buster/sdcc/sdasz80.1.en.html)
 * [objdump(1)](https://manpages.debian.org/buster/binutils-common/objdump.1.en.html)
   or a similar tool to convert `.ihx` to `.bin`
 * `binpac8x.py` tool to convert `.bin` to `.8xp`.
   Download it from <https://www.cemetech.net/downloads/files/449/x449>
   or <https://gist.github.com/CoolOppo/e22f35ac2f7b7856349e>
 * Perl and libraries `libconfig-ini-perl`, `libmime-base32-perl`
 * Optionally: POSIX `make` if you want to use the `Makefile`
 * Texas Instruments TI-84+ or compatible calculator and a means to transfer the
   program to it (e.g. I use
   [tilp(1)](https://manpages.debian.org/buster/tilp2/tilp.1.en.html))

Configuration
=============

If you want to run the program as depicted in the screenshots, edit the
following line from `Makefile`:

	BINPACK8X = /data/main/dpr/rr/wpru/ti84plus/binpac8x/binpac8x.py

Here, you need to give the path to your `binpac8x.py` (it is not included in
the repository!) Next, invoke the compilation as follows:

	make

In case you want to try out the program using your own TOTP seeds, they need to
be compiled in. This is a three-step process where data flows as follows:

	|            secret_keys_to_inc.pl      compile+link
	                       |                     |
	+----------------+      \    +----------+     \    +------------+
	| secretkeys.ini | --------> | keys.inc | -------> | trtotp.8xp |
	+----------------+           +----------+          +------------+

## `secretkeys.ini`

This file configures the password to be used and the individual TOTP seeds.
Here is a sample `secretkeys.ini` with two entries:

~~~{.ini}
[global]
password=123456

[Test Service]
timestep=30
digits=6
key=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

[Other Key]
timestep=30
digits=6
key=JBSWY3DPEHPK3PXP
~~~

Section `global` configures the password to be used in plain text. Note that
only uppercase letters and digits are supported. In the example, it's the
classic `123456` (most common password on the Internet, DO NOT USE!)

Subsequent sections are formatted as follows:

	[Service Name]
	timestep=TOTP-specific timestep configuration, typical.: 30
	digits=Number of output digits expected, typical.: 6, others: 7, 8.
	key=Base32-representation of the seed. Spaces are to be removed.

While you can define an arbitrary number of services this way, remember the
maximum of 12 entries before the calculator's memory runs out.

## `secret_keys_to_inc.pl`

Having prepared the `secretkeys.ini` file, it needs to be transformed into an
“include” file that conforms to the C syntax. At this stage, the TOTP seeds
are encrypted using the password and the (not very secure!) scheme described
before.

To simplify this process, script `secret_keys_to_inc.pl` can be used:

	./secret_keys_to_inc.pl secretkeys.ini > keys.inc

NOTE: If you want to customize the “salt” used for hashing your passwords -- it
is recommendable to do this from a security point of view -- edit files
`secret_keys_to_inc.pl` and `trtotp.c` and replace the following bytes by
your own 32 random bytes:

	0xc5, 0xf7, 0x40, 0xd8, 0x1f, 0xda, 0x49, 0xb6,
	0xe6, 0x1b, 0x5c, 0xee, 0xbd, 0x29, 0xbb, 0xa5,
	0x89, 0x99, 0x93, 0x8f, 0x4b, 0x8b, 0xca, 0x40,
	0xbb, 0x5a, 0xb4, 0x05, 0x1b, 0x9a, 0xe7, 0x4d

In case you struggle to get something random enough, try `xxd < /dev/urandom`.
Of course, having changed the random bytes, it is necessary to re-run the
`secret_keys_to_inc.pl` invocation to encrypt the TOTP seeds according to the
changed “encryption scheme”.

Afterwards, compile and test the TOTP application :)

Compilation Details
===================

In case you do not want to use the `Makefile`, here are the individual steps for
compilation:

	# Optional step: Encrypt and provide TOTP seeds
	./secret_keys_to_inc.pl secretkeys.ini > keys.inc
	
	# Compile assembly startup routine
	sdasz80 -p -g -o tios_crt0.rel tios_crt0.s
	
	# Compile application
	sdcc --no-std-crt0 --code-loc 40347 --data-loc 0 --std-sdcc99 -mz80 \
		--opt-code-size --reserve-regs-iy -o trtotp.ihx tios_crt0.rel \
		trtotp.c
	
	# Convert .ihx -> .bin
	objcopy -I ihex -O binary trtotp.ihx trtotp.bin
	
	# Convert .bin -> .8xp
	binpac8x.py trtotp.bin

Afterwards, transfer `trtotp.8xp` to your calculator (or an emulator --
safety first!)

Usage
=====

In case it is not obvious from the screenshots already, here is a short
usage guide from the “user's perspective”.

First, start the program on the calculator:

 * Press 2nd->CATALOG, Select `Asm(`, Press ENTER.
 * Press PRGM, Select `TRTOTP`, Press ENTER.
 * Press ENTER to evaluate the input line

The program will ask you to enter the password. Use number keys or ALPHA-A,
ALPHA-B etc. for letters. After giving the password, press ENTER.

The next screen shows the list of menu items available. Use UP/DOWN arrows to
select the item of interest and press ENTER to compute the TOTP code for it.

The first menu item is special: It displays a decimal number that is the first
byte of the key used to decrypt the TOTP seeds. In case you mistyped your
password, this value will differ from the one you'd usually observe for the
correct password. This is the only immediate indicator as to whether the
entered password was correct on the previous screen.

Press DEL to exit the program.

If you are on the screen that displays the current TOTP code, you can update
the displayed code by pressing `1` and return to the previous menu item with
`0`.

Do not leave the application open for long: Not only is it a security issue.
There is also a memory leak whenever an application is quit due to an event
like auto-off or manually turning the calculator off, its memory is not freed.
Given that this application is quite memory hungry, this will usually mean that
it is not possible to run it again until the memory is reset entirely!

License Information
===================

For the complete license texts, see file `LICENSE.txt` in the repository.
Note that unlike many other Ma_Sys.ma projects, this is licensed GPL-2.0+.

	Ma_Sys.ma TRTOTP 1.0.0, Copyright (c) 2021 Ma_Sys.ma.
	For further info send an e-mail to Ma_Sys.ma@web.de.

	This project contains code under the following copyrights:

	Copyright (C) 2005, 2006 Free Software Foundation, Inc.
	Copyright (c) 2020 Jacob Shin (deuteriumoxide)
	Copyright (c) 2014 Nestor Soriano Vilchez (www.konamiman.com)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software Foundation,
	Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

See Also
========

## Similar Project

I am not the first one to have this idea, btw:
<https://github.com/jshin313/ti-authenticator>,
introductory post:
<https://www.cemetech.net/forum/viewtopic.php?t=16823>

## Resources on Programming the TI 84+ and related

 * Tutorial for programming the calculator using SDCC:
   <https://www.cemetech.net/forum/viewtopic.php?t=7087>
 * Table of functions (much better than relying on the `.inc` file alone!)
   <https://wikiti.brandonw.net/index.php?title=Category:83Plus:BCALLs:By_Name>
 * GNU Assembler for z80 <https://packages.debian.org/buster/binutils-z80>
 * Another assembler <https://packages.debian.org/buster/z80asm>
 * Another compiler <https://z88dk.org/site/>
 * For a more capable TI-84+ _CE_:
   <https://github.com/CE-Programming/toolchain>, Introduction page
   <https://codewalr.us/index.php?topic=1050.0>
 * Z80 Assembly Tutorial for TI-83+:
   <https://tutorials.eeems.ca/ASMin28Days/lesson/toc.html>
 * Z80 calling convention for SDCC
   <http://bricologica.com/projects/z80/2015/08/17/z-80-code-generation-with-sdcc.html>

## Resources regarding TOTP

 * Datetime to Unix timestamp routine:
   <https://github.com/rsyslog/rsyslog/blob/master/runtime/datetime.c>
