from mnemonic import Mnemonic as mc
from binascii import unhexlify,hexlify
import sys

class key(object):
	def __init__(self,m):
		self.version = "ver1.0"
		self.m = m

	def b2h(self,b):
		h = hexlify(b)
		return h if sys.version < '3' else h.decode('utf8')

	@staticmethod
	def to_mnemonic(data,lang="english"):
		data = data if type(data) == bytes else bytes(data,"utf8")
		m = key(m = mc(lang).to_mnemonic(unhexlify(data)))
		return m

	@staticmethod
	def generate(strength,lang="english"):
		#gen_mnemonic
		m = key(m = mc(lang).generate(strength))
		return m

	def seed(self,passphrase=""):
		return mc.to_seed(self.m, passphrase=passphrase)

	def cointype(self):
		return None
