from setuptools import setup, find_packages

DESCRIPTION = "A pure python implementation of the RSA encryption algorithm"

setup(
    name="u_micro_rsa",
    version="2021.5",
    license="GNU General Public License Version 3.0",
    author="Z-40",
    description=DESCRIPTION,
    url="https://github.com/Z-40/MicroRSA",
    install_requires=[],
    keywords=["python", "RSA", "encryption", "public-key-cryptography"],
    packages=["micro_rsa"],
    license_file="microrsa/license.txt"
)
