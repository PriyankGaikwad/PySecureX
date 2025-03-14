from setuptools import setup, find_packages

setup(
    name="pysecurex",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pycryptodome",
        "cryptography",
        "requests"
    ],
    author="Priyank Gaikwad",
    description="Advanced Python security library for encryption, hashing, passwords, and network security.",
    long_description=open("docs/README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/PriyankGaikwad/PySecureX",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
