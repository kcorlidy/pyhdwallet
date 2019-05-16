from mnemonic import Mnemonic
import unittest
import binascii
from pyhdwallet.hdwallets import bips


class test(unittest.TestCase):

	def test_parameter(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
		store = bip44.generator(7)
		store.__dict__ # all parameters

	def test_to_json(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
		store = bip44.generator(7)
		store.to_json()

	def test_to_csv(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
		store = bip44.generator(7)
		store.to_csv()

if __name__ == "__main__":

	unittest.main()