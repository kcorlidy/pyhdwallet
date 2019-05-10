from hdwallets import bips, bip39
import unittest

bip44 = {
0: ["m/44'/0'/0'/0/0", '13nhUXwZ3bepwxk13uB4Ev7AxFCur94ApK', 'L27CuC8mVsKfuQvcmSH1FvrTLNGaZ8AQoMyVDWr3eLriqrxWV4Cy', ('91d732cc137a993e005e53cfa83021053158c529621bad64177b7a567f4d6aa3', '027f76d7f3c5231433938aef17170231f4b5355e6a1a654c991aa2b9e559dba288')],
 1: ["m/44'/0'/0'/0/1", '1LbZWyPf12kkxfGStKM5xBuPF7pbdVkyCA', 'L1MVY6zDFS4cyuyYEywUmgdhfZQYRnyv83UB4TSy2wDo58X3vEKn', ('7b5a58601121bdca647a947bee655ab70f1e6e32a541c5a389f4543802c60963', '03073c3f007e55272fa328ac4ab6118730d9c673ca39f8e6c36e28c8a5a4e3c2fe')],
  2: ["m/44'/0'/0'/0/2", '1E8JuaorwCR2FAmXnLTT3V762r7YmXRWkx', 'KxrYXbjLQYdmeoEYfvSZzJFb8wXrtw5bkfisq5VxGHFJRBUh9RQq', ('30c9341987825d95615a8ec5cf57cdf7ddd3129dd99dea83643cdce8c7b95f82', '030d0a0ea5e05550df8b5682758b83295c63eb472440dd260a7026dbf493c9a8b2')],
   3: ["m/44'/0'/0'/0/3", '1DH8zN99q9N325pnk7XRGBBk4bFdteJLnL', 'L5kWW3oBM3kcU4VAXdkSg1uJvJYdzhb83EKwJT2i8dwiGobju4eE', ('fe8b0a2955674cca0362869d31e96546e7135d693610bea4711e3ca6a9f5c587', '02907ab96874e6088f2804ba0f2e9a322a9c57585799d36ee8c6b3770a49fb2d9c')],
    4: ["m/44'/0'/0'/0/4", '17jh2Cm6aPs3oVGPp5fvrWYfVCpY7tx7hn', 'L1GGZqx6337nqLFETYa5MtVoAeQaHredvZ2cAj2y2kYSakLVwHGZ', ('78aa6a30212e8be9cd672b9f30dd7c46b0139651057d48fe8e14f9ed5c5bb925', '03b11f43d5b6684db65590063b9ec57f8b3c1edc2de4eb54b8cc8f8cde97806709')],
     5: ["m/44'/0'/0'/0/5", '1HEDvJMQqVSKrG3s3S3L1waSUeeJATquP7', 'KwynGCtxjzer6ttjnZ9hGHUrJL9Mndv1XfM7Cra2jPg2CQbSYvRE', ('16abe38365e59b1dee92fdc9433ed968ea375562a7691161d2c9b791e884946e', '02da449fb6f67c5481292afde2736e662a6abd2e3d3b5bf10a18a6299ffb21a2b4')],
      6: ["m/44'/0'/0'/0/6", '1FWhPtcKxmUmsE2sdyScE3h4WMF5SpfZe1', 'KwEfGQpN3DyPKKzbMc3WhXXez8kTYxqUe46bEnbTtfaVbXw3qeSG', ('007d12002a00b53656ad1090463f28bc7e6d28e57a335368b70ccbfbbb62a792', '021c4f07797db034c6598c0ed739ca469a0e20ecfed396224facca383e6d581086')]}

bip49 = {0: ["m/49'/0'/0'/0/0", '3PRoiesDDHaRAsWVDV2ekSMf3Y3KApkyEH', 'L2qHrMfSHbsLBbTkDpXb9dysffNhefJwk7GtA7WNbkmQX5Nh81zD', ('a77dad30e1a39d6dbd2dbd1bf5740777ac6c74855693d91f77fafd96e4867f8c', '0361ad6aa540cb92c0477b482f43cb52a8315dd6a0b0cc797243ed249d47089db3')],
 1: ["m/49'/0'/0'/0/1", '3G2nbzaULHix8SyTh7pvwZBRJ72D8ES7ch', 'L4uEEw2icNWnnjyqfurpbse2q9myBp4TpGNqZ1pEKtGV4t4xHJ1x', ('e531025f665161e23d7bb4c2375e8e722bebbf77952fc96a307410ff8afc8c37', '03b93df395a70335dcd0a59ae92f969ee694422c59d8f589a011a1d5db562ed76e')],
  2: ["m/49'/0'/0'/0/2", '3AY4mGdQRpjieturtK3LPtUGdncdyzHk2K', 'L5fYCeUo5vXgRBtsEdkPDAgGZALT76ojG7KtSffrWjHwSX9cVwFE', ('fbfc6b5067c75a063a98577a7e7d25246773181aad44d083725e4711c690f864', '03bacac51042902a7962548dc7eea3b3ae79048f83aef2f111732265a54e62abe5')],
   3: ["m/49'/0'/0'/0/3", '3Jp3yqwDKbyUedYUURN8p9m4BMsqb1vHcF', 'KzBPfLD6cYud4w6498qgyFKr8mhzgCUyMRqhHmAGHjLPEjG8MPm9', ('5851ab82de4ca48f258c521d1ba99cc7239c750c561d997091902ad03af1d061', '031fc95e4f66f84589bfb6b2dd1ad904adacb4cd48476d4eed9a055914ddde9a23')],
    4: ["m/49'/0'/0'/0/4", '3Ee3eJcCkoSf2pcXrURMFWczsyJ3bWdCud', 'L3zo5m7vAZ3eAiVu1PJuNuNgJNguKhVpMghEoixNUdts2VNHmmLm', ('ca37b00ed301d453a586f89b5dac65db9a3c26391a997981e8d6ef9edaedda81', '023161e241147641ef3028b3ea66b6d8c2c47b7a437aaa3ad6a0a651a6a88f32f3')],
     5: ["m/49'/0'/0'/0/5", '35v5QMKVcf1A7LEzYT6kghLio2R6eD9LXd', 'L3fnSCoLdrQ3jCEmwKPQ2rj144WKjpMswB8HkDEFAyogkQrcZJMs', ('c06ffdd9732eb8ce49258ccd6744db65ff90894f3205b425d059de7e9f4fe000', '021b453051a32c3c4b7430567e2bd0b1439b6e9b239d84ae96537dd9df48eaf84b')],
      6: ["m/49'/0'/0'/0/6", '39xrKxSBDjMEtMDqnACVyDFWsJ1yzXvM6u', 'L1ZZ58FR92vXofbpCX9UF4fducR5d3yjz5AUjysXcaGGSAaxsLdk', ('818eb985178f2e2e18ef9435d9a5a2198b2037bee9561aa9630c863afa3d9102', '03e1e49250dd4f21cd8e1ba40b957d044165fe76477296d2cf7c73f3373b24bc58')]}


bip84 = {0: ["m/84'/0'/0'/0/0", 'bc1ql292pj7jjg74ztw4verxmpz3kpmqcjumt7sldc', 'L289ARYoycWTbSxsGF12KS2vhJP66S4y23ruLgyXUGiWYLYv8gUG', ('9252688773fc238e7855cb1df91fc16094acb42b224d378d3ff9a1d6782846df', '03174dace7a87d75467b2adea368af5601128ae1c96b83d66916322d1a1df86280')],
 1: ["m/84'/0'/0'/0/1", 'bc1q2gpc2nj25w0uttkfs99x9jxtcchm3ll2jmqugt', 'L1M4U8AXTGHFh33WQuxKF1cTzN4jQG32N1gzrtAH9ANW1VrViGz9', ('7b216c81f38aefacaa9d8743b35a23cfda522eb219be5fa3bb4cc02193e592e4', '026619b770249bd7e18a23e4ac0cf8e72b5a860882a299cd7be9aef747af8d7889')], 2: ["m/84'/0'/0'/0/2", 'bc1qm5ndvv8th2mpzefjf5fnqa7544u53677e9erjz', 'L47puxGGnHPJtMT6HzbcCbmb6YXVVKLKdLYMppJftwtZAnaPYvYp', ('cdd5b7b9728d1b52a8aaf5b51013aeefba51c66e141f300b5e067fb9b354242e', '0200fb4b17625d5f5f8c8704e58b91eea4558bc9f064759abf0a1ac129f1ba99b0')],
  3: ["m/84'/0'/0'/0/3", 'bc1qgmfdyqvnt4rp8a406yf8re2rgmedhtxu9add6a', 'Kz2sE64K5PFg5UXQGCGXXbP9gjiEZw6tjKoDg3B4PVUJXmYhUHBD', ('53eefe88215f3beba8f49adfc76dcc28861906287c0bbbf6c6bea05b49f4c6d6', '03a5cfd2b04577adf72291749a6e908f3116878c7c15aaaf8fecfe8fbb486154c7')],
   4: ["m/84'/0'/0'/0/4", 'bc1q34qu7g92qtwl6760ckctylv6fl24rwx6cgxetl', 'L5d5FMqw2bxGsvFHRjtfZx8sVYicNktknRPjhTXmfPC2HZTfu9j4', ('fab7d390384ca07566d6e72e6bd26f782fb8d9fda42abec7209a7dadee6de8dd', '023006a259e33b8d5368ce304c1382e4c7241ee93e66e10e3d489c13d8fbfa2b85')],
    5: ["m/84'/0'/0'/0/5", 'bc1qy0m3vye2s9hh8v9ujpwy0ue6eskpcagg4epr4s', 'L4hYfLSYmGRz1nBiR4vSicZEThSYE7HWropiFrngSofVPWyEbVAZ', ('df2e7b91f7b5749f6f56664bbaa93892f86df1ca043d77a93be58dcd387cb0f9', '0323f37ad40f9e9d65947c083170452b2687b693dd30610285e0255fd755d2d1c5')],
     6: ["m/84'/0'/0'/0/6", 'bc1qvx4m552wg0d25ft96pysnztt2mvl995skxyxg0', 'L42GJyJqKpdYY98CXu9ZyngyWhfGTqq9DC3ydkPwjJRzmYDvZ6y7', ('caf9353152c871ddebb32c98de214baaf2e69051d0375af28b31bd009ff111a0', '03bf62bb8f4176210318c29009736fd1f3844eca60113eab5d036b799c496dc81a')]}

class Derivation_test(unittest.TestCase):
	"""docstring for Derivation_test"""
	def test_bip44(self):
		entropy = bip39.to_mnemonic(entropy="a9495fe923ce601f4394c8a7adadabc3").seed()
		bip = bips.initialize("m/44'/0'/0'/0",seed=entropy)
		self.assertEqual(bip.exkey()[0],"xprv9za8mkD4SQHLRzKtPBvZK5WgiVkcchBNH7YAZVr9JQJbUKVWu12BRigThsmwHRJXaUMjua5MrjSa6JFREVuu19dywkGZchaHYp18KGArWaR")
		self.assertEqual(bip.gen(7),bip44)

	def test_bip49(self):
		entropy = bip39.to_mnemonic(entropy="a9495fe923ce601f4394c8a7adadabc3").seed()
		bip = bips.initialize("m/49'/0'/0'/0",seed=entropy)
		self.assertEqual(bip.exkey()[0],"yprvAMA64twBQxXTiLD8Mrcbqj9DrJLmKoTFEHAMTMZ9uYcwZ9xnmvwPP9Hmx5sMComtLSjsxEdxK615eqnJRFJsCngk87rdKGeY6752yiHP5mA")
		self.assertEqual(bip.gen(7),bip49)


	def test_bip84(self):
		entropy = bip39.to_mnemonic(entropy="a9495fe923ce601f4394c8a7adadabc3").seed()
		bip = bips.initialize("m/84'/0'/0'/0",seed=entropy)
		self.assertEqual(bip.exkey()[0],"zprvAfMVBbtYFkvnAK4F3eWJikburFJgTFLgYt4hVmL1kzr7PMFhci5fDu2bvztHP6JcbPQxMgTa65dRw1mYSBqDZ3HxnhN91k9PUsjjeSueLQv")
		self.assertEqual(bip.gen(7),bip84)
		

if __name__ == "__main__":
	unittest.main()
