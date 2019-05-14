from ._bip32 import BIP32Key
from binascii import unhexlify,hexlify
import sys
import sqlite3
from mnemonic import Mnemonic
import re
from pprint import pprint
print = pprint
from collections import OrderedDict
import json
import csv

def b2h(b):
	h = hexlify(b)
	return h if sys.version < '3' else h.decode('utf8')

def random_seed():
	return bip39.generate(128).seed()

class bips(object):
	def __init__(self, entropy = None, passphrase = "", mnemonic = None,
				 path = None, bip=44, cointype="bitcoin", testnet=False):
		self._entropy 		= entropy
		self.seed 			= None
		self.mnemonic 		= mnemonic
		self.path 			= path
		self.passphrase 	= passphrase
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None
		self.accounts 		= {}
		self.bip 			= bip
		self.bip32_root_key = None
		self.bip32_ext_key 	= None
		self.cointype		= cointype
		self.testnet		= testnet
		self.initialize

	def root_key2seed(root_key):
		"""
			NotImplementedError this function
		"""
		raise NotImplementedError

	@property
	def initialize(self):
		"""
			Initialize the fundamental parameters that we need through giving data
			Priority: Seed > Mnemonic > Entropy
			
			return None
		"""

		# When see is empty, so create seed if Mnemonic or _entropy has passed
		if self.mnemonic and not self._entropy:
			self.seed = bip39(self.mnemonic).seed(self.passphrase)

		elif self._entropy:
			tp = bip39.to_mnemonic(entropy=self._entropy)
			self.mnemonic = tp.m
			self.seed = tp.seed(self.passphrase)

		else:
			raise AttributeError("If you must specify entropy or mnemonic.")

		# validate path
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path  
		state = False if self.path[0].lower() != "m" or self.path[1] not in ["44'","49'","84'",None] else True 
		
		if state == False:
			raise RuntimeError("Path error:please give a correct path")

		self.bip = int(path[1][:-1]) if path[-1] else None

		# preparing generate child-key
		self.bip32ex_path()

		# self.entropy = self.mnemonic = self.passphrase = None # clear privacy

	def bip32ex_path(self):
		"""
			analysis the giving path, save rook key and extend key
			return None
		"""
		k = BIP32Key.fromEntropy(self.seed, testnet=self.testnet)

		if not self.bip32_root_key:
			# store root key.
			self.bip32_root_key = (k.ExtendedKey(private=False, encoded=True),
						k.ExtendedKey(private=True, encoded=True))

		if self.path[-1]:
			for _, p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'"))+self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3:
					self.accounts[self.showpath(self.path)[:-1]] = (k.ExtendedKey(),
																	k.ExtendedKey(private=False))
		
		self.k = k
		self.bip32_ext_key = (k.ExtendedKey(private=False, encoded=True),
						k.ExtendedKey(private=True, encoded=True))

	def index(self,n):
		"""
			return ChildKey(n)
		"""
		return self.k.ChildKey(n)

	def account(self):
		"""
			return (Account Extended Private key and Public Key)
		"""
		return self.accounts

	def address(self, k = None):
		"""
			bip44 -> P2PKH
			bip49 -> P2WPKH-nested-in-P2SH 
			bip84 -> P2WPKH
			return address
		"""
		if self.bip == 44:
			return self.k.Address() if not k else k.Address()
		elif self.bip == 49:
			return self.k.P2WPKHoP2SHAddress() if not k else k.P2WPKHoP2SHAddress()
		elif self.bip == 84:
			return self.k.P2WPKHAddress() if not k  else k.P2WPKHAddress()	
		
	def exkey(self):
		"""
			return (BIP32 Extended Private kye and Public Key)
		"""
		return self.k.ExtendedKey(bip=self.bip,cointype=self.cointype),self.k.ExtendedKey(private=False,bip=self.bip,cointype=self.cointype)

	def cokey(self , k = None):
		"""
			return (Derived coin Private key and Public Key)
		"""
		key = (self.k.PrivateKey(),self.k.PublicKey()) if k == None else (k.PrivateKey(),k.PublicKey())
		return  b2h(key[0]),b2h(key[1])

	def wif(self, k = None):
		"""
			return WalletImportFormat
		"""
		return self.k.WalletImportFormat() if k == None else k.WalletImportFormat()

	def generator(self, n = 1):
		"""
			`n` is how many accounts you need. 
			create multiple Account that contain `path`, `wif`, `address`, `pubkey`, `prikey`
			return FileStruct
		"""
		main_path = self.showpath(self.path)
		self.next()
		
		gen_list = []
		for i in range(n):
			index = self.index(i)
			subpath = main_path + str(i)
			wif = self.wif(index)
			address = self.address(index)
			key = self.cokey(index) #pri, pub
			gen_list.append([subpath, address, key[1], key[0], wif])

		return self.details(addr=gen_list)

	def showpath(self, p):
		"""
			p -> giving path list
			return path
		"""
		return "".join([s+"/" for s in self.path])

	def next(self):
		self.address()
		self.cokey()
		self.wif()

	def details(self, addr):
		"""
			address -> list of Derived Addresses

			return FileStruct
		"""
		__format = OrderedDict({
			"Entropy": self._entropy,
			"Mnemonic": self.mnemonic,
			"Seed": hexlify(self.seed).decode(),
			"BIP32 Root Key": self.bip32_root_key,
			"Coin": self.cointype,
			"Purpose": self.path[1][:-1],
			"Coin": self.path[2][:-1],
			"Account": self.path[3][:-1],
			"External/Internal": self.path[4],
			"Account Extended Private Key": None,
			"Account Extended Public Key": None,
			"BIP32 Derivation Path": self.showpath(self.path)[:-1],
			"BIP32 Extended Pri/Pub Key": self.bip32_ext_key, 
			"Derived Addresses": addr
		})
		return FileStruct(__format)

class FileStruct(object):

	def __init__(self, details = None):
		self.details = details
		self.__dict__.update({ re.sub(r"\W", "_", k) :v for k,v in details.items()})

	def to_csv(self):
		with open('{}.csv'.format(self.Mnemonic), 'w+', newline='') as csvfile:
			fieldnames = ['Path', 'Address', 'Public Key', 'Private Key', 'Wallet import form']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

			writer.writeheader()
			for path, address, pub, pri, wif in self.Derived_Addresses:
				writer.writerow({'Path': path,
								 'Address': address,
								 "Public Key": pub,
								 "Private Key": pri,
								 "Wallet import form": wif})

	def to_json(self):
		with open('{}.json'.format(self.Mnemonic), "w+") as fd:
			json.dump(self.details, fd, indent=4)

	def to_sql(self):
		"""
			NotImplementedError
		"""
		raise NotImplementedError

class bip39(object):
	def __init__(self, m):
		self.version = "ver1.0"
		self.m = m

	@staticmethod
	def to_mnemonic(entropy, lang="english"):
		entropy = entropy if isinstance(entropy, bytes) else bytes(entropy,"utf8")
		return bip39(m = Mnemonic(lang).to_mnemonic(unhexlify(entropy)))

	@staticmethod
	def generate(strength, lang="english"):
		return bip39(m = Mnemonic(lang).generate(strength))

	def seed(self, passphrase=""):
		return Mnemonic.to_seed(self.m, passphrase=passphrase)

