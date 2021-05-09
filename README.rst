pyAesCrypt
===============
.. image:: https://travis-ci.com/marcobellaccini/pyAesCrypt.svg?branch=master
    :target: https://travis-ci.com/marcobellaccini/pyAesCrypt
.. image:: https://pepy.tech/badge/pyaescrypt
    :target: https://pepy.tech/project/pyaescrypt

About pyAesCrypt
--------------------------
pyAesCrypt is a Python 3 file-encryption module and script that uses AES256-CBC to encrypt/decrypt files and binary streams.

pyAesCrypt is compatible with the `AES Crypt`_ `file format`_ (version 2).

It is Free Software, released under the `Apache License, Version 2.0`_.

pyAesCrypt is brought to you by Marco Bellaccini - marco.bellaccini(at!)gmail.com.
 
IMPORTANT SECURITY NOTE: version 2 of the AES Crypt file format does not authenticate the "file size modulo 16" byte. This implies that an attacker  
with write access to the encrypted file may alter the corresponding plaintext file size by up to 15 bytes.

NOTE: there is no low-level memory management in Python, hence it is not possible to wipe memory areas were sensitive information was stored.

Module usage example
------------------------
Here is an example showing encryption and decryption of a file:

.. code:: python

    import pyAesCrypt
    password = "please-use-a-long-and-random-password"
    # encrypt
    pyAesCrypt.encryptFile("data.txt", "data.txt.aes", password)
    # decrypt
    pyAesCrypt.decryptFile("data.txt.aes", "dataout.txt", password)

**This is the most straightforward way to use pyAesCrypt, and should be preferred.**

If you need to specify a custom buffer size (default is 64KB), you can pass it as an optional argument:

.. code:: python

    import pyAesCrypt
    # custom encryption/decryption buffer size (default is 64KB)
    bufferSize = 128 * 1024
    password = "please-use-a-long-and-random-password"
    # encrypt
    pyAesCrypt.encryptFile("data.txt", "data.txt.aes", password, bufferSize)
    # decrypt
    pyAesCrypt.decryptFile("data.txt.aes", "dataout.txt", password, bufferSize)

In case you need it, you can work with binary streams too:

.. code:: python

    import pyAesCrypt
    from os import stat, remove
    # encryption/decryption buffer size - 64K
    # with stream-oriented functions, setting buffer size is mandatory
    bufferSize = 64 * 1024
    password = "please-use-a-long-and-random-password"
    
    # encrypt
    with open("data.txt", "rb") as fIn:
        with open("data.txt.aes", "wb") as fOut:
            pyAesCrypt.encryptStream(fIn, fOut, password, bufferSize)
    
    # get encrypted file size
    encFileSize = stat("data.txt.aes").st_size
    
    # decrypt
    with open("data.txt.aes", "rb") as fIn:
        try:
            with open("dataout.txt", "wb") as fOut:
                # decrypt file stream
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize, encFileSize)
        except ValueError:
            # remove output file on error
            remove("dataout.txt")

you can also perform in-memory encryption/decryption (using BytesIO):

.. code:: python

    import pyAesCrypt
    import io
    
    bufferSize = 64 * 1024
    password = "please-use-a-long-and-random-password"
    
    # binary data to be encrypted
    pbdata = b"This is binary plaintext \x00\x01"
    
    # input plaintext binary stream
    fIn = io.BytesIO(pbdata)
    
    # initialize ciphertext binary stream
    fCiph = io.BytesIO()
    
    # initialize decrypted binary stream
    fDec = io.BytesIO()
    
    # encrypt stream
    pyAesCrypt.encryptStream(fIn, fCiph, password, bufferSize)
    
    # print encrypted data
    print("This is the ciphertext:\n" + str(fCiph.getvalue()))
    
    # get ciphertext length
    ctlen = len(fCiph.getvalue())
    
    # go back to the start of the ciphertext stream
    fCiph.seek(0)
    
    # decrypt stream
    pyAesCrypt.decryptStream(fCiph, fDec, password, bufferSize, ctlen)
    
    # print decrypted data
    print("Decrypted data:\n" + str(fDec.getvalue()))



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

FAQs
------------------------
- *Is pyAesCrypt malware?*

  **NO!** Of course it isn't!

  Nevertheless, being a module, it can be used by any other software, including malware.
  
  In fact, it has been reported that it is used as crypto library by some ransomware.

.. _AES Crypt: https://www.aescrypt.com
.. _file format: https://www.aescrypt.com/aes_file_format.html
.. _Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
