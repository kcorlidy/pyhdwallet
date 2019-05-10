from setuptools import setup

version = "0.1"

REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name="pyhdwallet",
    version=version,
    packages=[
        "pyhdwallet",
        "pyhdwallet._bip32",
        "pyhdwallet.examples"
    ],
    package_data={
        '_bip32': ['*.db', '*.json'],
    },
    entry_points={'console_scripts': [
        'examples = pyhdwallet.examples.test:main'
    ]},
    install_requires=REQUIREMENTS,
    author="kcorlidy Chain",
    author_email="kcorlidy@outlook.com",
    url="https://github.com/kcorlidy/pyhdwallet",
    license="http://opensource.org/licenses/MIT",
    description="Hierarchical Deterministic (HD) key creation tools"
)
