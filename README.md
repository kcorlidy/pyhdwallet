# HD-address-generator
HD-adddress-generator is used to generate different kinds of addresses,which allowed bip32 bip39 bip44 and bip84.If you want,you could create bip141 by using my bip32

## About my bip32 code
My bip32 code is from bip32utils,but i add P2WPKH address and rewrite bip32 extend key version by using sqlite3.So we can add new key version easily. Read more key version : https://github.com/satoshilabs/slips/blob/master/slip-0132.md

How to generate coin address 
----------------------------
```
from Derivation_Path import bips
from root_key import key
    entropy = key.to_mnemonic(data="a9495fe923ce601f4394c8a7adadabc3").seed()
    bip = bips.initialize("m/49'/0'/0'/0",seed=entropy)
    bip.exkey()   #return BIP32 Extended Private&Public Key
    bip.cokey()   #retrun privkey and pubkey
    bip.wif()     #return WalletImportFormat privkey
    bip.address() #return address
    
    bip.gen(5)    #return information {index:[subpath,address,wif,cokey]} 
    such as: 
    #{0: ["m/49'/0'/0'/0/0", '3PRoiesDDHaRAsWVDV2ekSMf3Y3KApkyEH', 'L2qHrMfSHbsLBbTkDpXb9dysffNhefJwk7GtA7WNbkmQX5Nh81zD', ('a77dad30e1a39d6dbd2dbd1bf5740777ac6c74855693d91f77fafd96e4867f8c', '0361ad6aa540cb92c0477b482f43cb52a8315dd6a0b0cc797243ed249d47089db3')]}
```
