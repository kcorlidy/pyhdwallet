# HD address generator
HD adddress generator is used to generate addresses, which allowed bip32 bip39 bip44 and bip84.

## Create your addresses

```python
from pyhdwallet.hdwallets import bips
entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
store = bip44.generator(7)
store.Derived_Addresses
"""
[["m/44'/0'/1'/1/0", '1yVbVptFimQUrJk6fUZQtKV6esabYcZkD', '02c955e7e0dc721259561a6eb403b22da2ac8bb261a13c10cbd5879997ab31bd24', '2c4df4eaa52c07b4e809eace15999b828e95362c999097ec1761e318a0a50bf2', 'KxhqGih7Q8g7sBavSHKXTyQ4uwTrYYneTYfvws18wbTQPrBMBtuA'], 
["m/44'/0'/1'/1/1", '1P5e3XUMFo9W5Rf7hvHYsFQXLv4m7zfWZ7', '020ba35dc73e437a07112c25b5279b15e79db9af5111720a3707fb572ad96f17d2', 'f40945de4563c1807d30b3e45e6b1424fc37e1224c07e5ab7ffffbc1197f2881', 'L5Q5uZqPpxqu6PcabSNzNetp5Jb2cfGtQgbQvKi5Z9p4M9pNXpbv'], ["m/44'/0'/1'/1/2", '16yggzHujezdoRpSRKkPr1ReRUvxeiafKz', '03bbeb2f23acbc2c38b738efaab4d36a1bfcfabe830dea971a6eaf146f305d4703', '2c2bcb8bdfac6a457c4511f505aedaa141cc02e4e5c361b20910b21525bcccde', 'KxhaE7BPnPNXwi6Nwuvw7zyUKsi37LA6Uv6WEMScGrbGTXfUGLE2'], ...
"""
```

## To JSON

```python
from pyhdwallet.hdwallets import bips
entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
store = bip44.generator(8)
store.to_json()
"""
{
    "Entropy": "a62e81c7dcfa6dcae1f066f1aacddafa",
    "Mnemonic": "plate inject impose rigid plug tornado march art vast filter issue village",
    "Seed": "99b5ccefea83beb7dd42e62bb3bceb965b935c26c85290febc48f571060a1d8c8f4e847c45b67864977ae1d0c1e83e6ae0019a78c571c0fc3fdee6e020329664",
    "BIP32 Root Key": [
        "xpub661MyMwAqRbcFv9eYCnrjUJGKgRXmHi4im3sECGnr7v1VXxVKE97KTjPXE5QcBivKvpvVFVJ9NjAZ4noh7o7oMS966ZJYwVB7nR1P4DXrju",
        "xprv9s21ZrQH143K3S5BSBFrNLMXmeb3MpzDMY8GRosBHnP2cjdLmgprmfQufvWS6gv5BeRL4smJzTo9SnT33PBis5Ywq79L3fJmkRj7niu1fjo"
    ],
    "Coin": "0",
    "Purpose": "44",
    "Account": "1",
    "External/Internal": "1",
    "Account Extended Private Key": null,
    "Account Extended Public Key": null,
    "BIP32 Derivation Path": "m/44'/0'/1'/1",
    "BIP32 Extended Pri/Pub Key": [
        "xpub6FAbA3mm4NoAfDM5nMDRbpVmJmfJo8ePKVKqKN7xbJifJZuXcZtvpYXHm2ZhuHwHZaVq6D2RDZxqsLDVbyASJZJCpY3orEjEepVq8iqiNN2",
        "xprvA2BEkYEsE1EsSjGcgKgREgZ2kjppPfvXxGQEWyiM2yBgRmaP52agGkCoui4ppuDdLxAbdcCgP2yf3FtAmppie9pyBoBpQEUzWNpe5VmfqmD"
    ],
    "Derived Addresses": [
        [
            "m/44'/0'/1'/1/0",
            "1yVbVptFimQUrJk6fUZQtKV6esabYcZkD",
            "02c955e7e0dc721259561a6eb403b22da2ac8bb261a13c10cbd5879997ab31bd24",
            "2c4df4eaa52c07b4e809eace15999b828e95362c999097ec1761e318a0a50bf2",
            "KxhqGih7Q8g7sBavSHKXTyQ4uwTrYYneTYfvws18wbTQPrBMBtuA"
        ],
        ...
"""
```

## To CSV

```python
from pyhdwallet.hdwallets import bips
entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
bip44 = bips(path="m/44'/0'/1'/1",entropy=entropy)
store = bip44.generator(9)
store.to_csv()

"""
Path,Address,Public Key,Private Key,Wallet import form
m/44'/0'/1'/1/0,1yVbVptFimQUrJk6fUZQtKV6esabYcZkD,02c955e7e0dc721259561a6eb403b22da2ac8bb261a13c10cbd5879997ab31bd24,2c4df4eaa52c07b4e809eace15999b828e95362c999097ec1761e318a0a50bf2,KxhqGih7Q8g7sBavSHKXTyQ4uwTrYYneTYfvws18wbTQPrBMBtuA
m/44'/0'/1'/1/1,1P5e3XUMFo9W5Rf7hvHYsFQXLv4m7zfWZ7,020ba35dc73e437a07112c25b5279b15e79db9af5111720a3707fb572ad96f17d2,f40945de4563c1807d30b3e45e6b1424fc37e1224c07e5ab7ffffbc1197f2881,L5Q5uZqPpxqu6PcabSNzNetp5Jb2cfGtQgbQvKi5Z9p4M9pNXpbv
...
"""
```



## Cointype it has

| Coin | pubkey | privkey | Address_Encoding | BIP32_Path | prefix | bip  |
| ---- | ------ | ------- | ---------------- | ---------- | ------ | ---- |
| bitcoin | 0488b21e | 0488ade4 | P2PKH or P2SH | m/44'/0' | xpub-xprv | 44   |
| bitcoin | 049d7cb2 | 049d7878 | P2WPKH in P2SH | m/49'/0' | ypub-yprv | 49   |
|bitcoin|04b24746|04b2430c|P2WPKH|m/84'/0'|zpub-zprv|84|
|litecoin|019da462|019d9cfe|P2PKH or P2SH|m/44'/2'|Ltub-Ltpv|44|
|litecoin|01b26ef6|01b26792|P2WPKH in P2SH|m/49'/1'|Mtub-Mtpv|49|
|bitcoin testnet|043587cf|04358394|P2PKH or P2SH|m/44'/1'|tpub-tprv|44|
|bitcoin testnet|044a5262|044a4e28|P2WPKH in P2SH|m/49'/1'|upub-uprv|49|
|bitcoin testnet|045f1cf6|045f18bc|P2WPKH|m/84'/1'|vpub-vprv|84|
|litecoin testnet|0436f6e1|0436ef7d|P2PKH or P2SH|m/44'/1'|ttub-ttpv|44|
|vertcoin|0488b21e|0488ade4|P2PKH or P2SH|m/44'/28'|vtcp-vtcv|44|

