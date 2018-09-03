from bip32utils import BIP32Key,Base58
from root_key import key
from binascii import unhexlify,hexlify
import sys
import sqlite3


class bip44(object):
	def __init__(self,e = None,path = None):
		self.e 				= self.warning() if e == None else e
		self.path 			= path
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None

	@staticmethod
	def initialize(p,seed = None):
		p = p.split("/")
		state = False if p[0].lower() != "m" or "44" not in p[1] else True 
		#if false mean user gave an unexpected path
		if state == False:
			raise Exception("Path error:please give a correct path")	
		if seed == None:
			print("If you do not specify a seed, you will use a random seed")		
		bip = bip44(path=p,e=seed)
		bip.bip32ex_path()
		return bip

	def warning(self):
		seed = key.generate(128).seed()
		print("Using random seed",self.b2h(seed))
		return seed

	def Account(self):
		#Account Extended Private/Public Key
		pass

	def address(self,k = None):
		return self.k.Address() if k == None else k.Address()

	def bip32ex_path(self): 
		k = BIP32Key.fromEntropy(self.e)
		for p in self.path:
			if "'" in p and p != 'm':
				k = k.ChildKey(int(p.strip("'"))+self.BIP32_HARDEN)
			elif p != 'm':
				k = k.ChildKey(int(p))
		self.k = k

	def index(self,n):
		k = self.k.ChildKey(n)
		return k
		
	def exkey(self):
		return k.ExtendedKey(),k.ExtendedKey(private=False)

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
		def showpath(p):
			return "".join([s+"/" for s in self.path])
		main_path = showpath(self.path)
		self.clear()
		for i in range(0,n):
			index = self.index(i)
			subpath = main_path+str(i)
			wif = self.wif(index)
			address = self.address(index)
			key = self.cokey(index)


	def dump(self):
		#generate amount of address,pubkey,privkey into db
		conn = sqlite3.connect('{}.db'.format("d"))
		c = conn.cursor()
		c.execute('''CREATE TABLE stocks
		             (date text, trans text, symbol text, qty real, price real)''')
		c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")
		conn.commit()
		conn.close()

	def clear(self):
		#bip32utils used generator,which influenced the next result.So need to clear it
		self.bip32ex_path()
		self.address()
		self.cokey()
		self.wif()
	

class bip49(object):
	def __init__(self, arg):
		self.arg = arg
		

if __name__ == '__main__':
	bip = bip44.initialize("m/44'/0'/0'/0")
	bip.entropy = key.to_mnemonic(data="a9495fe923ce601f4394c8a7adadabc3").seed()
	bip.gen(5)
