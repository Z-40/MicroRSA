from setuptools import setup, find_packages

DESCRIPTION = "A pure python implementation of the RSA encryption algorithm"

setup(
    name="u_micro_rsa",
    version="2021.1",
    license="GPL v3",
    author="Z-40",
    description=DESCRIPTION,
    url="https://github.com/Z-40/MicroRSA",
    install_requires=[],
    keywords=["python", "RSA", "encryption", "public-key-cryptography"],
    packages=["micro_rsa"]
)
