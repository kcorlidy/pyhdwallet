from bip32 import BIP32Key
from root_key import key
from binascii import unhexlify,hexlify
import sys
import sqlite3


class bips(object):
	def __init__(self,e = None,path = None,bip=44,cointype="bitcoin",testnet=False):
		self.e 				= self.warning() if e == None else e
		self.path 			= path
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None
		self.accounts 		= {}
		self.bip 			= bip
		self.cointype		= cointype
		self.testnet		= testnet

	@staticmethod
	def initialize(p,seed = None,cointype="bitcoin",testnet=False):
		p = p.split("/")
		p = p + [None] if p[0] == p[-1] else p  
		state = False if p[0].lower() != "m" or p[1] not in ["44'","49'","84'",None] else True 
		#if false mean user gave an unexpected path
		
		if state == False:
			raise Exception("Path error:please give a correct path")	
		if seed == None:
			print("If you do not specify a seed, you will use a random seed")
		bip = int(p[1][:-1]) if p[-1] else None
		
		bip_ = bips(path=p,e=seed,bip=bip,cointype=cointype,testnet=testnet)
		bip_.bip32ex_path()
		if not bip:
			# BIP32 Root Key
			return bip_.k.b2h(bip_.k.PublicKey())
		return bip_

	def warning(self):
		seed = key.generate(128).seed()
		print("Using random seed",self.b2h(seed))
		return seed

	def account(self):
		#Account Extended Private/Public Key
		return self.accounts

	def address(self,k = None):
		if self.bip == 44:
			return self.k.Address() if k == None else k.Address()
		elif self.bip == 49:
			return self.k.P2WPKHoP2SHAddress() if k == None else k.P2WPKHoP2SHAddress()
		elif self.bip == 84:
			return self.k.P2WPKHAddress() if k == None else k.P2WPKHAddress()
		
	def bip32ex_path(self): 
		k = BIP32Key.fromEntropy(self.e,testnet=self.testnet)
		if self.path[-1]:
			for _,p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'"))+self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3:
					self.accounts[self.showpath(self.path)[:-1]] = (k.ExtendedKey(),k.ExtendedKey(private=False))
		self.k = k

	def index(self,n):
		k = self.k.ChildKey(n)
		return k
		
	def exkey(self):
		#BIP32 Extended Private/Public Key
		return self.k.ExtendedKey(bip=self.bip,cointype=self.cointype),self.k.ExtendedKey(private=False,bip=self.bip,cointype=self.cointype)

	def cokey(self , k = None):
		#Derived coin Private/Public Key
		key = (self.k.PrivateKey(),self.k.PublicKey()) if k == None else (k.PrivateKey(),k.PublicKey())
		return  self.b2h(key[0]),self.b2h(key[1])

	def wif(self,k = None):
		return self.k.WalletImportFormat() if k == None else k.WalletImportFormat()

	@property
	def entropy(self):
		return self.e

	@entropy.setter
	def entropy(self,e):
		self.e = e
		print("Seed has changed,hex value:",self.b2h(e))

	def b2h(self,b):
		h = hexlify(b)
		return h if sys.version < '3' else h.decode('utf8')

	def gen(self,n = 1):
		main_path = self.showpath(self.path)
		self.clear()
		gen_list = {}
		for i in range(0,n):
			index = self.index(i)
			subpath = main_path+str(i)
			wif = self.wif(index)
			address = self.address(index)
			key = self.cokey(index) #key[0] priv key[1] pub
			gen_list[i] = [subpath,address,wif,key]

		return {k:gen_list[k] for k in sorted(gen_list.keys())}

	def showpath(self,p):
		return "".join([s+"/" for s in self.path])

	def clear(self):
		#bip32utils used generator,which influenced the next result.So need to clear it
		self.address()
		self.cokey()
		self.wif()
	
if __name__ == '__main__':
	entropy = key.to_mnemonic(data="a9495fe923ce601f4394c8a7adadabc3").seed()
	bip = bips.initialize("m/84'/0'/0'/0",seed=entropy)
	#print(bip.exkey())
	#print(bip.address())
	print(bip.gen(7))
