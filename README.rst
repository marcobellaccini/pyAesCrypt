pyAesCrypt
===============
.. image:: https://travis-ci.org/marcobellaccini/pyAesCrypt.svg?branch=master
    :target: https://travis-ci.org/marcobellaccini/pyAesCrypt

About pyAesCrypt
--------------------------
pyAesCrypt is a Python 3 file-encryption module and script that uses AES256-CBC to encrypt/decrypt files.

pyAesCrypt is compatible with the `AES Crypt`_ `file format`_ (version 2).

The script is Free Software, released under the `Apache License, Version 2.0`_.

pyAesCrypt is brought to you by Marco Bellaccini - marco.bellaccini(at!)gmail.com.
 
IMPORTANT SECURITY NOTE: version 2 of the AES Crypt file format does not authenticate the "file size modulo 16" byte. This implies that an attacker  
with write access to the encrypted file may alter the corresponding plaintext file size by up to 15 bytes.

NOTE: there is no low-level memory management in Python, hence it is not possible to wipe memory areas were sensitive information was stored.

Module usage example
------------------------
Here is an example showing encryption and decryption of a file:

.. code:: python

    import pyAesCrypt
    # encryption/decryption buffer size - 64K
    bufferSize = 64 * 1024
    password = "foopassword"
    # encrypt
    pyAesCrypt.encryptFile("data.txt", "data.txt.aes", password, bufferSize)
    # decrypt
    pyAesCrypt.decryptFile("data.txt.aes", "dataout.txt", password, bufferSize)

Script usage examples
------------------------
Encrypt file test.txt in test.txt.aes:

	pyAesCrypt -e test.txt

Decrypt file test.txt.aes in test.txt:

	pyAesCrypt -d test.txt.aes
	
Encrypt file test.txt in test2.txt.aes:

	pyAesCrypt -e test.txt -o test2.txt.aes

Decrypt file test.txt.aes in test2.txt:

	pyAesCrypt -d test.txt.aes -o test2.txt

.. _AES Crypt: https://www.aescrypt.com
.. _file format: https://www.aescrypt.com/aes_file_format.html
.. _Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
