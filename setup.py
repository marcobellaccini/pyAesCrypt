from setuptools import setup, find_packages

readme = open('README.rst', 'r')
README_TEXT = readme.read()
readme.close()

setup(name='pyAesCrypt',
      version='0.1.2',
      packages = find_packages(),
      description='Encrypt and decrypt files in AES Crypt format (version 2)',
      long_description = README_TEXT,
      author='Marco Bellaccini',
      author_email='marco.bellaccini[at!]gmail.com',
      url='https://pypi.python.org/pypi/pyAesCrypt/',
      license='Apache License 2.0',
      scripts=['pyAesCrypt'],
      install_requires=['pycrypto'],
      keywords = "AES Crypt encrypt decrypt",
     )