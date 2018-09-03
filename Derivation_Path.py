from bip32utils import BIP32Key,Base58
from root_key import key
from binascii import unhexlify,hexlify
import sys

class bip44(object):
	def __init__(self, e = None , path = None):
		self.e 				= key.generate(128).seed()
		self.path 			= path
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None

	@staticmethod
	def path(p):
		p = p.split("/")
		state = False if p[0].lower() != "m" or "44" not in p[1] else True 
		#if false mean user gave an unexpected path
		if state:
			 return bip44(path=p)
		else:
			raise Exception("Path error:please give a correct path")

	def Account(self):
		#Account Extended Private/Public Key
		pass

	def address(self):
		return self.k.Address()

	def bip32ex_key(self):
		k = BIP32Key.fromEntropy(self.e)
		for p in self.path:
			if "'" in p and p != 'm':
				k = k.ChildKey(int(p.strip("'"))+self.BIP32_HARDEN)
			elif p != 'm':
				k = k.ChildKey(int(p))
		self.k = k
		return k.ExtendedKey(),k.ExtendedKey(private=False)

	def key_pairs(self):
		#Derived Private/Public Key
		return self.b2h(self.k.PrivateKey()),self.b2h(self.k.PublicKey())

	def wif(self):
		return self.k.WalletImportFormat()

	@property
	def entropy(self):
		return self.e

	@entropy.setter
	def entropy(self,e):
		self.e = e

	def b2h(self,b):
		h = hexlify(b)
		return h if sys.version < '3' else h.decode('utf8')

	def gen(self):
		#generate amount of address,pubkey,privkey
		pass

if __name__ == '__main__':
	bip = bip44.path("m/44'/0'/0'/0/0")
	bip.entropy = key.to_mnemonic(data="a9495fe923ce601f4394c8a7adadabc3").seed()
	print(
		bip.bip32ex_key(),
		bip.address(),
		bip.key_pairs(),
		bip.wif())