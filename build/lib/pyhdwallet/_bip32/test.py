from bip32utils import Base58, BIP32Key
import codecs
def derive_address(mpk, path = []):
	pub = BIP32Key.fromExtendedKey(mpk)
	for child_index in path:
		pub = pub.ChildKey(child_index)
	print(codecs.encode(pub.PublicKey(),"hex"))
	return pub.P2WPKHAddress()


master_public_key='vprv9DMUxX4ShgxMMgUBH9eTvV9LbTnhuGZBcRh7hzishv7znvocnmDamqdxmutL5BXFXDAiWTr3kizhzdCy6tSjV9w9cHSaTNL4Rvt2jjTNBZm' # this can be xpub or ypub mpk
address = derive_address(master_public_key, [84+0x80000000, 0x80000000, 0x80000000,0,0]) # go for ./0/2 key derivation path
print(address)
#bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
#0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c