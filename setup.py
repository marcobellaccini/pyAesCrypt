import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

setup(name='pyAesCrypt',
    version='0.2.1',
    packages = find_packages(),
    include_package_data=True,
    description='Encrypt and decrypt files in AES Crypt format (version 2)',
    long_description = README,
    author='Marco Bellaccini',
    author_email='marco.bellaccini[at!]gmail.com',
    url='https://github.com/marcobellaccini/pyAesCrypt',
    license='Apache License 2.0',
    scripts=['bin/pyAesCrypt'],
    install_requires=['pycrypto'],
    keywords = "AES Crypt encrypt decrypt",
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ],
)
