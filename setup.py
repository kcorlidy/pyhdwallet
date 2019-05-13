from setuptools import setup, find_packages

version = "0.1"

setup(
    name = "pyhdwallet",
    version = version,
    packages = find_packages(),
    package_data = {
        '': ['_bip32/data/*.db'],
    },
    #data_files=[('pyhdwallet/_bip32/data/bip32version.db', 'pyhdwallet/_bip32/data')],
    install_requires = [
        "mnemonic",
        "ecdsa"],
    zip_safe=False,
    platforms="any",
    python_requires=">=3.5",
    author = "kcorlidy Chan",
    author_email = "kcorlidy@outlook.com",
    url = "https://github.com/kcorlidy/pyhdwallet",
    license = "http://opensource.org/licenses/MIT",
    description = "Hierarchical Deterministic (HD) key creation tools",
    long_description = ""
)
