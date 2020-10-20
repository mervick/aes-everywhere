import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aes-everywhere",
    packages=['AesEverywhere'],
    package_dir={'':'src'},
    version="1.2.9",
    author="Andrey Izman",
    author_email="izmanw@gmail.com",
    description="AES Everywhere - Cross Language Encryption Library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mervick/aes-everywhere",
    install_requires=['pycryptodomex'],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography"
    ],
    python_requires='>=2.7',
    project_urls={
        "Bug Tracker": "https://github.com/mervick/aes-everywhere/issues",
        "Source Code": "https://github.com/mervick/aes-everywhere",
    },
    test_suite="src/tests/test_aes256.py"
)
