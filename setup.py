from setuptools import setup, find_packages

setup(
    name="pysecurex",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "scikit-learn",
        "tensorflow",
        "argparse",
        "cryptography",
        "pillow",
        "pydub",
        "pycryptodome",
        "requests",
    ],
    author="Priyank Gaikwad",
    description="Advanced Python security library for encryption, hashing, passwords, network security, steganography, post-quantum cryptography, and AI-based threat detection.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/PriyankGaikwad/PySecureX",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "pysecurex=cli:main",
        ],
    },
    python_requires='>=3.6',
)
