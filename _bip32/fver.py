#!/usr/bin/env python
#
#fver.py -> find version

import sqlite3
import codecs
from binascii import hexlify
connection = sqlite3.connect(__file__[:-7]+"data/bip32version.db")

def query_ver(cointype="bitcoin",testnet=False,private=False,bip=44):
	#Param
	#
	#Cointype -> bitcoin(most of type), litecoin , vertcoin
	#
	#Bip -> 44 , 49 , 84
	#
	#Key -> private key / public key
	#
	#testnet -> True or False
	#
	c = connection.cursor()
	key = "pubkey" if not private else "privkey"
	cointype = cointype if not testnet else cointype+" testnet"
	c.execute("select {} from bip32version where coin='{}' and bip={}".format(key,cointype,bip))
	return [codecs.decode(e[0],"hex") for e in c.fetchall()]

def query_lsit(testnet=False,public=False):
	c = connection.cursor()
	key = "pubkey" if public else "privkey"
	cointype = "n" if not testnet else " "+"testnet"
	c.execute("select {} from bip32version where coin like '%{}'".format(key,cointype))
	l = list(bytes(e[0],"utf8") for e in c.fetchall())
	return l

if __name__ == '__main__':
	print(query_ver())
	print(query_lsit())
	connection.close()