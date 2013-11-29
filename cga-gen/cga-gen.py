#!/usr/bin/env python
##########################################################################
##                                                                      ##
## cga-gen.py - Generate a CGA and associated parameters using Scapy6.  ##
##                                                                      ##
## Copyright (C) 2013  Marc Buijsman                                    ##
##                                                                      ##
## This program is free software: you can redistribute it and/or modify ##
## it under the terms of the GNU General Public License as published by ##
## the Free Software Foundation, either version 3 of the License, or    ##
## (at your option) any later version.                                  ##
##                                                                      ##
## This program is distributed in the hope that it will be useful,      ##
## but WITHOUT ANY WARRANTY; without even the implied warranty of       ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        ##
## GNU General Public License for more details.                         ##
##                                                                      ##
##########################################################################

from netaddr.ip import IPNetwork, IPAddress
import netifaces as ni
import binascii as ba
import errno
from scapy6send.scapy6 import CGAgen


def usage(msg):
	print msg + '''

Usage: ''' + sys.argv[0] + ''' <public key> [<sec> <dad> <prefix> <ext1> <ext2> <ext3>...]
  public key   input file containing the public key in PEM PKCS8 format
  sec          (optional) the sec parameter (0 through 7); defaults to 0
  dad          (optional) perform duplicate address detection if equal to '1'
  prefix       (optional) the IPv6 prefix to concatenate the generated IPv6 identifier with;
                          by default, takes the 64-bit prefix of the first found IPv6 address currently in use
  ext1         (optional) first extension field
  ext2         (optional) second extension field
  ext3         (optional) third extension field
               more extension fields can be passed'''
	exit()


def main(prefix, pub_key, sec, ext, dad):
	try:
		pk = open(pub_key, 'rb').read()
	except IOError:
		usage("Could not open file '" + pub_key + "'.")

	if prefix == None:
		try:
			a = ni.ifaddresses('eth0')[10][0]['addr']
		except KeyError:
			usage("Could not get prefix: no IPv6 address found at 'eth0'; alternatively pass a prefix in command line argument.")
		try:
			m = ni.ifaddresses('eth0')[10][0]['netmask']
		except KeyError:
			usage("Could not get prefix: no subnet mask found at 'eth0'; alternatively pass a prefix in command line argument.")

		prefix = str(IPAddress(int(IPNetwork(a).network) & int(IPNetwork(m).network)))
	else:
		if prefix[-1] != ':':
			prefix = prefix + ':'
		if prefix[-2] != ':':
			prefix = prefix + ':'

	try:
		sec = int(sec)

		if sec < 0 or sec > 7:
			raise ValueError
	except ValueError:
		usage("The sec parameter must be an integer between 0 and 7.");

	try:
		(addr, params) = CGAgen(prefix, PubKey(pk), sec, ext, dad)
	except socket.error, v:
		if v[0] == errno.EPERM:
			usage("Need to be root to perform duplicate address detection.")
		else:
			usage("Invalid prefix.")

	mod = ba.b2a_base64(params.modifier)

	print "            CGA: " + addr
	sys.stdout.write("       modifier: " + mod.rstrip())

	try:
		md = open('mod.out', 'w')
		md.write(mod)
		print " (written to file 'mod.out')"
	except IOError:
		print " (could not write to file 'mod.out')"

	sys.stdout.write("collision count: " + str(params.ccount))

	if not dad:
		print " (did NOT perform duplicate address detection)"
	else:
		print


if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage("Generate a CGA and associated parameters using Scapy6.")

	pk = sys.argv[1]
	sec = 0
	px = None
	ext = []
	dad = False

	if len(sys.argv) > 2:
		sec = sys.argv[2]

	if len(sys.argv) > 3:
		if sys.argv[3] == '1':
			dad = True

	if len(sys.argv) > 4:
		px = sys.argv[4]

	if len(sys.argv) > 5:
		ext = sys.argv[5:]

	main(px, pk, sec, ext, dad)

