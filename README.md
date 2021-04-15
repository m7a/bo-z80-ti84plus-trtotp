---
section: 32
x-masysma-name: ti84plus/z80/trtotp
title: TOTP Program for TI 84+ Calculators
date: 2021/04/15 18:43:42
lang: en-US
author: ["Linux-Fan, Ma_Sys.ma (Ma_Sys.ma@web.de)"]
keywords: ["ti", "calculator", "totp", "crypto", "z80"]
x-masysma-version: 1.0.0
x-masysma-website: https://masysma.lima-city.de/32/ti84plus_z80_trtotp.xhtml
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

_TODO GIF-SCREENSHOT GOES HERE!_

This implementation supports multiple (12 seems to be the maximum) TOTP seeds
and allows them to be selected through an interactive menu displayed on the
calculator. In terms of algorithms, _only_ TOTP using a HMAC-SHA-1 is supported.

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

This proof of concept application propoes a sort of “might work” solution for
the second problem while leaving the first problem unresolved.

TOTP seeds are worth protecting while stored at rest. An usual modern approach
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
tell which of the tried passwords was correct.

The program presented here implements the generation of the one time pad from
the user's password as follows:

	_TODO ADDING A SALT IS THE MINIMUM WE COULD DO!_
	First 16 bytes of OTP key = md5(Password)
	Next 16 bytes of OTP key  = md5(previous 16 bytes of OTP key)

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

_TODO CONTINUE HERE_

; Configure your TOTP tokens here
; Process this file with `secret_keys_to_inc.pl` to generate `keys.inc` file.
; Recompile `trtotp.8xp` to send the changed keys to your calculator.
; Supports at most 12 entries!

Compilation
===========

Usage
=====

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
<https://github.com/jshin313/ti-authenticator>

## Resources on Programming the TI 84+ and related

 * GNU Assembler for z80 <https://packages.debian.org/buster/binutils-z80>
 * Another assembler <https://packages.debian.org/buster/z80asm>
 * Another compiler <https://z88dk.org/site/>
 * For a more capable TI-84+ _CE_: <https://github.com/CE-Programming/toolchain>
 * _TODO THERE IS MORE, MUCH MORE_
