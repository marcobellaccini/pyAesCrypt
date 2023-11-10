# ==============================================================================
# Copyright 2020 Marco Bellaccini - marco.bellaccini[at!]gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================

# ==============================================================================
# pyAesCrypt
#
# pyAesCrypt is a Python file-encryption utility that uses AES256-CBC to
# encrypt/decrypt files and binary streams.
# pyAesCrypt is compatible with the AES Crypt (https://www.aescrypt.com/)
# file format (version 2).
# It uses PyCA Cryptography for crypto primitives and the operating system's
# random number generator (/dev/urandom on UNIX platforms, CryptGenRandom
# on Windows).
#
# IMPORTANT SECURITY NOTE: version 2 of the AES Crypt file format does not
# authenticate the "file size modulo 16" byte. This implies that an attacker
# with write access to the encrypted file may alter the corresponding plaintext
# file size by up to 15 bytes.
#
# NOTE: there is no low-level memory management in Python, hence it is
# not possible to wipe memory areas were sensitive information was stored.
# ==============================================================================

# pyAesCrypt module

import io
import warnings
from os import path, remove, urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# pyAesCrypt version - now semver
version = "6.1.1"

# default encryption/decryption buffer size - 64KB
bufferSizeDef = 64 * 1024

# maximum password length (number of chars)
maxPassLen = 1024

# AES block size in bytes
AESBlockSize = 16


# password stretching function
def stretch(passw, iv1):

    # hash the external iv and the password 8192 times
    digest = iv1 + (16 * b"\x00")

    for i in range(8192):
        passHash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        passHash.update(digest)
        passHash.update(bytes(passw, "utf_16_le"))
        digest = passHash.finalize()

    return digest


# encrypt file function
# arguments:
# infile: plaintext file path
# outfile: ciphertext file path
# passw: encryption password
# bufferSize: optional buffer size, must be a multiple of
#             AES block size (16)
#             using a larger buffer speeds up things when dealing
#             with big files
#             Default is 64KB.
def encryptFile(infile, outfile, passw, bufferSize=bufferSizeDef):
    try:
        with open(infile, "rb") as fIn:
            # check that output file does not exist
            # or that, if exists, is not the same as the input file
            # (i.e.: overwrite if it seems safe)
            if path.isfile(outfile):
                if path.samefile(infile, outfile):
                    raise ValueError("Input and output files are the same.")
            try:
                with open(outfile, "wb") as fOut:
                    # encrypt file stream
                    encryptStream(fIn, fOut, passw, bufferSize)

            except IOError:
                raise ValueError("Unable to write output file.")

    except IOError:
        raise ValueError("Unable to read input file.")


# encrypt binary stream function
# arguments:
# fIn: input binary stream
# fOut: output binary stream
# passw: encryption password
# bufferSize: encryption buffer size, must be a multiple of
#             AES block size (16)
#             using a larger buffer speeds up things when dealing
#             with long streams
def encryptStream(fIn, fOut, passw, bufferSize=bufferSizeDef):
    # validate bufferSize
    if bufferSize % AESBlockSize != 0:
        raise ValueError("Buffer size must be a multiple of AES block size.")

    if len(passw) > maxPassLen:
        raise ValueError("Password is too long.")

    # generate external iv (used to encrypt the main iv and the
    # encryption key)
    iv1 = urandom(AESBlockSize)

    # stretch password and iv
    key = stretch(passw, iv1)

    # generate random main iv
    iv0 = urandom(AESBlockSize)

    # generate random internal key
    intKey = urandom(32)

    # instantiate AES cipher
    cipher0 = Cipher(algorithms.AES(intKey), modes.CBC(iv0), backend=default_backend())
    encryptor0 = cipher0.encryptor()

    # instantiate HMAC-SHA256 for the ciphertext
    hmac0 = hmac.HMAC(intKey, hashes.SHA256(), backend=default_backend())

    # instantiate another AES cipher
    cipher1 = Cipher(algorithms.AES(key), modes.CBC(iv1), backend=default_backend())
    encryptor1 = cipher1.encryptor()

    # encrypt main iv and key
    c_iv_key = encryptor1.update(iv0 + intKey) + encryptor1.finalize()

    # calculate HMAC-SHA256 of the encrypted iv and key
    hmac1 = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac1.update(c_iv_key)

    # write header
    fOut.write(bytes("AES", "utf8"))

    # write version (AES Crypt version 2 file format -
    # see https://www.aescrypt.com/aes_file_format.html)
    fOut.write(b"\x02")

    # reserved byte (set to zero)
    fOut.write(b"\x00")

    # setup "CREATED-BY" extension
    cby = "pyAesCrypt " + version

    # write "CREATED-BY" extension length
    fOut.write(b"\x00" + bytes([1 + len("CREATED_BY" + cby)]))

    # write "CREATED-BY" extension
    fOut.write(bytes("CREATED_BY", "utf8") + b"\x00" + bytes(cby, "utf8"))

    # write "container" extension length
    fOut.write(b"\x00\x80")

    # write "container" extension
    for i in range(128):
        fOut.write(b"\x00")

    # write end-of-extensions tag
    fOut.write(b"\x00\x00")

    # write the iv used to encrypt the main iv and the
    # encryption key
    fOut.write(iv1)

    # write encrypted main iv and key
    fOut.write(c_iv_key)

    # write HMAC-SHA256 of the encrypted iv and key
    fOut.write(hmac1.finalize())

    # encrypt file while reading it
    while True:
        # try to read bufferSize bytes
        fdata = fIn.read(bufferSize)

        # get the real number of bytes read
        bytesRead = len(fdata)

        # check if EOF was reached
        if bytesRead < bufferSize:
            # file size mod 16, lsb positions
            fs16 = bytes([bytesRead % AESBlockSize])
            # pad data (this is NOT PKCS#7!)
            # ...unless no bytes or a multiple of a block size
            # of bytes was read
            if bytesRead % AESBlockSize == 0:
                padLen = 0
            else:
                padLen = 16 - bytesRead % AESBlockSize
            fdata += bytes([padLen]) * padLen
            # encrypt data
            cText = encryptor0.update(fdata) + encryptor0.finalize()
            # update HMAC
            hmac0.update(cText)
            # write encrypted file content
            fOut.write(cText)
            # break
            break
        # ...otherwise a full bufferSize was read
        else:
            # encrypt data
            cText = encryptor0.update(fdata)
            # update HMAC
            hmac0.update(cText)
            # write encrypted file content
            fOut.write(cText)

    # write plaintext file size mod 16 lsb positions
    fOut.write(fs16)

    # write HMAC-SHA256 of the encrypted file
    fOut.write(hmac0.finalize())


# decrypt file function
# arguments:
# infile: ciphertext file path
# outfile: plaintext file path
# passw: encryption password
# bufferSize: optional buffer size, must be a multiple of AES block size (16)
#             using a larger buffer speeds up things when dealing with
#             big files
#             Default is 64KB.
def decryptFile(infile, outfile, passw, bufferSize=bufferSizeDef):
    try:
        with open(infile, "rb") as fIn:
            # check that output file does not exist
            # or that, if exists, is not the same as the input file
            # (i.e.: overwrite if it seems safe)
            if path.isfile(outfile):
                if path.samefile(infile, outfile):
                    raise ValueError("Input and output files are the same.")
            try:
                with open(outfile, "wb") as fOut:
                    try:
                        # decrypt file stream
                        decryptStream(fIn, fOut, passw, bufferSize)
                    except ValueError as exd:
                        # should not remove output file here because it is still in use
                        # re-raise exception
                        raise ValueError(str(exd))

            except IOError:
                raise ValueError("Unable to write output file.")
            except ValueError as exd:
                # remove output file on error
                remove(outfile)
                # re-raise exception
                raise ValueError(str(exd))

    except IOError:
        raise ValueError("Unable to read input file.")


# decrypt stream function
# arguments:
# fIn: input binary stream
# fOut: output binary stream
# passw: encryption password
# bufferSize: decryption buffer size, must be a multiple of AES block size (16)
#             using a larger buffer speeds up things when dealing with
#             long streams
# inputLength: input stream length (DEPRECATED)
def decryptStream(fIn, fOut, passw, bufferSize=bufferSizeDef, inputLength=None):
    if inputLength is not None:
        warnings.warn(
            "inputLength parameter is no longer used, and might be removed in a future version",
            DeprecationWarning,
            stacklevel=2,
        )
    # validate bufferSize
    if bufferSize % AESBlockSize != 0:
        raise ValueError("Buffer size must be a multiple of AES block size")

    if len(passw) > maxPassLen:
        raise ValueError("Password is too long.")

    if not hasattr(fIn, "peek"):
        fIn = io.BufferedReader(getBufferableFileobj(fIn), bufferSize)

    fdata = fIn.read(3)
    # check if file is in AES Crypt format (also min length check)
    if fdata != b"AES":
        raise ValueError("File is corrupted or not an AES Crypt (or pyAesCrypt) file.")

    # check if file is in AES Crypt format, version 2
    # (the only one compatible with pyAesCrypt)
    fdata = fIn.read(1)
    if len(fdata) != 1:
        raise ValueError("File is corrupted.")

    if fdata != b"\x02":
        raise ValueError(
            "pyAesCrypt is only compatible with version "
            "2 of the AES Crypt file format."
        )

    # skip reserved byte
    fIn.read(1)

    # skip all the extensions
    while True:
        fdata = fIn.read(2)
        if len(fdata) != 2:
            raise ValueError("File is corrupted.")
        if fdata == b"\x00\x00":
            break
        fIn.read(int.from_bytes(fdata, byteorder="big"))

    # read external iv
    iv1 = fIn.read(16)
    if len(iv1) != 16:
        raise ValueError("File is corrupted.")

    # stretch password and iv
    key = stretch(passw, iv1)

    # read encrypted main iv and key
    c_iv_key = fIn.read(48)
    if len(c_iv_key) != 48:
        raise ValueError("File is corrupted.")

    # read HMAC-SHA256 of the encrypted iv and key
    hmac1 = fIn.read(32)
    if len(hmac1) != 32:
        raise ValueError("File is corrupted.")

    # compute actual HMAC-SHA256 of the encrypted iv and key
    hmac1Act = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac1Act.update(c_iv_key)

    # HMAC check
    if hmac1 != hmac1Act.finalize():
        raise ValueError("Wrong password (or file is corrupted).")

    # instantiate AES cipher
    cipher1 = Cipher(algorithms.AES(key), modes.CBC(iv1), backend=default_backend())
    decryptor1 = cipher1.decryptor()

    # decrypt main iv and key
    iv_key = decryptor1.update(c_iv_key) + decryptor1.finalize()

    # get internal iv and key
    iv0 = iv_key[:16]
    intKey = iv_key[16:]

    # instantiate another AES cipher
    cipher0 = Cipher(algorithms.AES(intKey), modes.CBC(iv0), backend=default_backend())
    decryptor0 = cipher0.decryptor()

    # instantiate actual HMAC-SHA256 of the ciphertext
    hmac0Act = hmac.HMAC(intKey, hashes.SHA256(), backend=default_backend())

    # decrypt ciphertext, until last block is reached
    last_block_reached = False
    while not last_block_reached:
        # read data
        cText = fIn.read(bufferSize)

        # end of buffer
        if len(fIn.peek(32 + 1)) < 32 + 1:
            last_block_reached = True
            cText += fIn.read()
            fs16 = cText[-32 - 1]  # plaintext file size mod 16 lsb positions
            hmac0 = cText[-32:]
            cText = cText[: -32 - 1]

        # update HMAC
        hmac0Act.update(cText)
        # decrypt data and write it to output file
        pText = decryptor0.update(cText)

        # remove padding
        if last_block_reached:
            toremove = (16 - fs16) % 16
            if toremove:
                pText = pText[:-toremove]

        fOut.write(pText)

    # HMAC check
    if hmac0 != hmac0Act.finalize():
        raise ValueError("Bad HMAC (file is corrupted).")

# BufferableFileobj class
# A fileobj suitable as input to io.BufferedReader
class BufferableFileobj:
    def __init__(self, fileobj):
        self.__fileobj = fileobj
        self.closed = False

    def readable(self):
        return True

    def read(self, n = -1):
        return self.__fileobj.read(n)

    def readinto(self, b):
        rbuf = self.read(len(b))
        n = len(rbuf)
        b[0:n] = rbuf
        return n

# Returns input argument if it is suitable as input to io.BufferedReader,
#  otherwise an instance of BufferableFileobj with input argument as
#  backing fileobj
def getBufferableFileobj(fileobj):
    noattr = object()
    for attr in ('readable','readinto','closed'):
        if getattr(fileobj, attr, noattr) == noattr:
            return BufferableFileobj(fileobj)
    return fileobj
