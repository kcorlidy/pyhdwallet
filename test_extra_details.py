from mnemonic import Mnemonic
import unittest
import binascii
from hdwallets import bips

_store = [
["m/44'/0'/0'/0/0", '1HnA8fYPskppWonizo8v1owqjBDMviz5Zh', 'KzR58Tj1WkLvMJmyZzt3P4KTLJpv2tn7xK32nfHGNq9Ffw8WLUEc', ('5f5b55e76d05be90bdd523483386b8d418412dbe04dd398155c486319fb260f8', '02707f1e1a0e1ea7ba8ce83710604304fa85f995b6b0d15ff752cf70602cf4757e')], 
["m/44'/0'/0'/0/1", '19UbynsayGFyzSttsyaWAScUoDJV44hukC', 'L48hJkym4z3WDu9gbeRgdF67FWYbeD7kmnxVWkqb1a6TSm44oEJY', ('ce48243f664126598cfef576e42c261fd3f260ad3e5140f22a8aca473d3748cf', '036409b451fa2d626376dc63c49f787716a8b823bc72aac0052c43c2a780e1133f')], 
["m/44'/0'/0'/0/2", '1A5YmdnXm1BFTciqDgU7jNGMagRiydAKN2', 'L4qwB74LW3w935dEDzzFxoMfyhX3oToP1CKdkX9npAuDRWqSg2pj', ('e37f2baae76a1d720a4b06668b653b14640ff1467fc23e710d2c091ad210a32d', '033ee2fb84b95cec5e5d111e901f8487395d821993806414da7d8ee01cb1e7941a')], 
["m/44'/0'/0'/0/3", '1GoD7BUF8oPUkjuv4NoPx74aRaeb2BRKyH', 'L3Bm5RDRX5xt6oy5xy2b8yK7kf3F8wqykoTR1jsLW6mbyy42tHhn', ('b2056aa4154117140046f873597978cadcc3f2b1cce6301bf7d4745d73428388', '03b444e59c92359d85e56a6de86143456be93f00b6d6b52dd2ef6d5cfc2d56ee83')], 
["m/44'/0'/0'/0/4", '1JDtA64hxnsCcrk6dibaFEXH5ytL2coy44', 'KzVJ8nTJLLCC2TkxRtXtbA3WixPXz6wG15MkXsN9kwDKG3QPfhyn', ('6187a692b16e465d05a2037f095fef2e401ba78bcd390bc7234605252bcf3afb', '035851a2e3d42b3fa0eaee904c6f81c3fee2c71dacf1a1db7caab580edaa202417')], 
["m/44'/0'/0'/0/5", '12SDdnhhtqqXUpt9NCXAj7Biq7U8LmCTYG', 'L4VkN6BVzhmzrLCo1AKV1BbuAD5aanftNc5LDi6uCd9cqhnkv8PS', ('d91cb3ada28d82c0ae1df62a047b6c2542c0806b9e93cf02cfce9b79731af060', '03cb51f0e1f70b6dcf053d9d2c13cbf9cef747d8456861ba95e60a37b55e95b067')], 
["m/44'/0'/0'/0/6", '17sdDw3rkKqt46Dn1RBay6Xs8cPspBNr34', 'KyGrxM8rdTcdQogdXULuoZoubzQmHy5sUVee9Z718Zy8XBvhtSiG', ('3d4bbff776685615f8aa27032f140cd926b56534cc9d57a3ddb6a4ae47a5b2da', '03925a483d2aa23b78e71b37a8c1621f99bf81bd0b2fae6157b288e7eef23aba7d')]]

_store2 = [
["m/44'/0'/1'/0/0", '12kapsW4B5uTuVUkVaLDhXXLtGVa6AkRmC', 'L5PhLqhKHSsn4QFCfnjsngJWx9CedWmHojLrLAe8GtEknC1K7DxD', ('f3d609bc6ba670a7b98f93ec6d8ff8abdff9f7f3c8e119fab792d77b1fd4fbc3', '03ce67d28da94ff1e16d9d0c2446f8eb28b8d316f7e8ffa1a8e44b4be03e58d2f6')], 
["m/44'/0'/1'/0/1", '16e3VAThoHK7vCcRmboj2b7Mj4yBZpGdtE', 'L4M5DHZjqHnp3jqvfshjJnN6b99JJeFZ3CLNzEGeNUaa8wEZSfeX', ('d4a63bf33d51ee94d3112db4a34b9b5aa2398f57e7f3e7e4a5b69f528b19ad42', '024e2da3e34b3569d28b4ec24b190fe59f58d6d0fb70d57a91956fe370884e03d1')], 
["m/44'/0'/1'/0/2", '17re8XtKdM8X1vPdEUCFV1ZRcKSJzRN2zX', 'L29xKCBpe7PiKoYoUCXSnXBCtNu3hqpa6LpUKCiAo7szQ7fHZWyM', ('93412abf4127a28007f8cbfd5de5d2d92ff25bd041c9fec6576233b6a7394a8f', '0215d50a375dab5cb7617cc395485171a7ccdd6a7a4c81b5f6f2ab7013f30dc3da')], 
["m/44'/0'/1'/0/3", '1JhY3b1i4yDVgqcS3uCpvokHxqzfMTccAP', 'Kx6L6visN4NcGaUNwQN1C8pKuGfL1hwFRye758xdAGmS5RTmDLw3', ('1a0a5ca9195a6f4d9be98f0ce53853f9703d622bf9d4c71bc7976f9106ea4a72', '03ec8e9eca46693cb63658a5d4796fc1e5be1ea372826274df17f20423482077a2')], 
["m/44'/0'/1'/0/4", '19KsmKPTsKGUpVRYJAemhd4stkm1uPWcbH', 'L5hqhsRnRAZRSwPxyARRuagiVkY3FXHjkECXTHc89p9jayoH9nXr', ('fd2b8e571d290706853d20e80d242406ed65b7f878a80927275a5f5c12200492', '03e145815f618231df0b30a48a038beebe3700cc3ac5195fef6b0a57eedb3c81f9')], 
["m/44'/0'/1'/0/5", '1ApVc7KSa1kYdLyESZuunGDuXAMdmAipZ4', 'Kx2RzYeJ7eccMkL2GnaALS47TQRnY7rGZDJ93E84624Kt24nS5HC', ('1808f396602c7e14e7881fe6eec28fbb09d64d86483ccf107854467f2f774a4e', '026e49981794302541ee6f0e80bad02ed2e4db0db0d2db69f70cad8e793205750a')], 
["m/44'/0'/1'/0/6", '1D9UtkvW2HC3Sv8yV3yBax391tJqNTaBxH', 'L3ey85qkYs4xoBGbLHPcxWbPdb8eLHEVqjWB5NA8A7G3neSt2rvU', ('c004901f42083ff9bd30fe5c0bb87e26dcfb83235f828ba2337242a292c2caa3', '039672129b0cd9572da7dd35153367f8042e1683ad6695e4ff02caea5ac5369cea')]]


_store3 = [["m/44'/0'/1'/1/0", '1yVbVptFimQUrJk6fUZQtKV6esabYcZkD', 'KxhqGih7Q8g7sBavSHKXTyQ4uwTrYYneTYfvws18wbTQPrBMBtuA', ('2c4df4eaa52c07b4e809eace15999b828e95362c999097ec1761e318a0a50bf2', '02c955e7e0dc721259561a6eb403b22da2ac8bb261a13c10cbd5879997ab31bd24')], 
["m/44'/0'/1'/1/1", '1P5e3XUMFo9W5Rf7hvHYsFQXLv4m7zfWZ7', 'L5Q5uZqPpxqu6PcabSNzNetp5Jb2cfGtQgbQvKi5Z9p4M9pNXpbv', ('f40945de4563c1807d30b3e45e6b1424fc37e1224c07e5ab7ffffbc1197f2881', '020ba35dc73e437a07112c25b5279b15e79db9af5111720a3707fb572ad96f17d2')], 
["m/44'/0'/1'/1/2", '16yggzHujezdoRpSRKkPr1ReRUvxeiafKz', 'KxhaE7BPnPNXwi6Nwuvw7zyUKsi37LA6Uv6WEMScGrbGTXfUGLE2', ('2c2bcb8bdfac6a457c4511f505aedaa141cc02e4e5c361b20910b21525bcccde', '03bbeb2f23acbc2c38b738efaab4d36a1bfcfabe830dea971a6eaf146f305d4703')], 
["m/44'/0'/1'/1/3", '1Lh4tXeofLfAbVDD3atAQkdCRkxcFhAUn2', 'L39hEpVay3MK9JcKCi9vBUVRucxRJfRmXgWWKZ2S2xa2SjhuX8Su', ('b0f54f5803eabd6709250867eaab3ce34c0472aa7df129a7434491c9e2d00a4b', '0340fe2307e55112a931015f4d4f5bca3db33a9701fc5231093f072244d5fa537d')], 
["m/44'/0'/1'/1/4", '1FoCybi5fYQJKeS7R51zQXcWr7G1GS7mPh', 'L1A8WRik474RSgfPcUJ8LNTpXBNSoGP1V7inFDw75zDEohHpFNtX', ('7581f07f81f36b0d0c73e66a632463717068206d0524bfc563c4ff7d575eb74f', '03281f680eb4f1d9acc027f8daf4deb945dee8c393e6f195e16eb018de1fe9a693')], 
["m/44'/0'/1'/1/5", '12evLedQFBBGRug7APoyjmtC76V7zsBpbi', 'L2JRbsZiTBdRczEJtwUPkA4buzP1QiAuJRLhQstwRn8sA8Q1hfNE', ('979cb20c895c20871cec6d0d6473087aade92288ae579b6c14667b123068ad78', '033f7e5b00c97a51f1738119b8e00b6bdd28a9ccf5ca6d1eff63771a1d86f9b904')], 
["m/44'/0'/1'/1/6", '1G5c4GNbRurqKHYy8eZnLP9Urv74DYj4J9', 'L3wS8fQM2RfwdXxLvaG6GmJAM6266vZEoJC4RGgkN1ZcWfHXjUoM', ('c87d07ab5d5aa18172dace1d0d8a14b02e9b42dbd7625b59f8e53d8301c154d1', '02a13b44dd15e5ac94d322c0cbe159c1da54ca86e14401d738c0645ef4803d552a')]]

class test_(unittest.TestCase):

	def test_to_seed_by_words(self):
		words = "plate inject impose rigid plug tornado march art vast filter issue village"
		passphrase = ""
		seed = Mnemonic.to_seed(words, passphrase)
		seed_ = b"99b5ccefea83beb7dd42e62bb3bceb965b935c26c85290febc48f571060a1d8c8f4e847c45b67864977ae1d0c1e83e6ae0019a78c571c0fc3fdee6e020329664"
		self.assertEqual(binascii.hexlify(seed), seed_)


	def test_to_accounts_by_words_passphrase(self):
		words = "plate inject impose rigid plug tornado march art vast filter issue village"
		passphrase = ""
		bip44 = bips(path="m/44'/0'/0'/0", mnemonic=words, passphrase=passphrase)

		# check root key
		root_key = "xprv9s21ZrQH143K3S5BSBFrNLMXmeb3MpzDMY8GRosBHnP2cjdLmgprmfQufvWS6gv5BeRL4smJzTo9SnT33PBis5Ywq79L3fJmkRj7niu1fjo"
		self.assertEqual(bip44.bip32_root_key[1],root_key)

		# check ext key
		ext_key = "xprv9zZ1h87W4nFTEURfantKV84sexNWnY4fAHt3gPAXSnX7dRZDoBDCx5e77CxZPe9sK5F2TBTwNLc5gCDGNYbyxSWJ6fayPkAZLuLuwVwPSoZ"
		self.assertEqual(bip44.bip32_ext_key[1],ext_key)

		# generate addresses
		store = bip44.generator(7).Derived_Addresses
	
		self.assertEqual(store, _store)

	def test_to_accounts_by_entropy(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/0'/0",entropy=entropy)
		store = bip44.generator(7).Derived_Addresses
		
		self.assertEqual(store, _store)

	def test_specified_account(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/0",entropy=entropy)
		store = bip44.generator(7).Derived_Addresses
		self.assertEqual(store, _store2)
	
	def test_specified_Internal(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
		store = bip44.generator(7).Derived_Addresses
		self.assertEqual(store, _store3)

	def test_to_json(self):
		entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
		bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
		store = bip44.generator(7)
		self.assertEqual(store.Derived_Addresses, _store3)
		store.to_json()

if __name__ == "__main__":

	unittest.main()