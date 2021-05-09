#==============================================================================
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
#==============================================================================

# test suite for pyAesCrypt

import unittest
import os
import shutil
import filecmp
import subprocess
from os.path import isfile
import pyAesCrypt

# test file directory name
tfdirname = 'pyAesCryptTF'

# test file path prefix
prefix = tfdirname + '/'

# suffix for encrypted files
encsuffix = '.aes'

# suffix for decrypted files
decsuffix = '.decr'

# file names
filenames = [prefix+'empty', prefix+'block', prefix+'defbuffer',
             prefix+'small', prefix+'med', prefix+'tbuf']

# generate encrypted file names
encfilenames = list()
for f in filenames:
    encfilenames.append(f+encsuffix)

# generate decrypted file names
decfilenames = list()
for f in filenames:
    decfilenames.append(f+decsuffix)

# buffer size
bufferSize = 64 * 1024

# test password
password = "foopassword!1$A"


# function for generating test files
def genTestFiles():
    # empty file
    with open(filenames[0], 'wb') as fout:
        fout.write(b'')
    # one AES block (16 bytes) file
    with open(filenames[1], 'wb') as fout:
        fout.write(os.urandom(16))
    # default buffer size file
    with open(filenames[2], 'wb') as fout:
        fout.write(os.urandom(bufferSize))
    # small file
    with open(filenames[3], 'wb') as fout:
        fout.write(os.urandom(4))
    # med-sized file
    with open(filenames[4], 'wb') as fout:
        fout.write(os.urandom(2*bufferSize+19))
    # 3-buffer sized file
    with open(filenames[5], 'wb') as fout:
        fout.write(os.urandom(3*bufferSize))


# function for corrupting files
def corruptFile(fp, offset):
    # open file
    with open(fp, 'r+b') as ftc:
        # get to the byte to corrupt
        ftc.seek(offset)
        # read the byte
        rb = ftc.read(1)
        # back to the byte to corrupt
        ftc.seek(offset)
        # if byte is 'X', overwrite with 'Y'
        if rb == b'\x58':
            ftc.write(b'\x59')
        # else overwrite with 'X'
        else:
            ftc.write(b'\x58')


# test encryption and decryption
# NOTE: SOME TESTS REQUIRE AES CRYPT INSTALLED, WITH ITS BINARY IN $PATH
class TestEncDec(unittest.TestCase):
    # fixture for preparing the environment
    def setUp(self):
        # make directory for test files
        try:
            os.mkdir(tfdirname)
        # if directory exists, delete and re-create it
        except FileExistsError:
            # remove whole tree
            shutil.rmtree(tfdirname)
            os.mkdir(tfdirname)
        # generate test files
        genTestFiles()
        
    def tearDown(self):
        # delete test files
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            os.remove(pt)
            os.remove(ct)
            os.remove(ou)
        # delete directory for test files
        os.rmdir(tfdirname)
    
    # test pyAesCrypt encryption/decryption
    def test_enc_pyAesCrypt_dec_pyAesCrypt(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            pyAesCrypt.encryptFile(pt, ct, password, bufferSize)
            # decrypt file
            pyAesCrypt.decryptFile(ct, ou, password, bufferSize)
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt, ou))

    # test pyAesCrypt encryption/decryption with default buffer size
    def test_enc_pyAesCrypt_dec_pyAesCrypt_defbufsize(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            pyAesCrypt.encryptFile(pt, ct, password)
            # decrypt file
            pyAesCrypt.decryptFile(ct, ou, password)
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt, ou))
            
    # test encryption with pyAesCrypt and decryption with AES Crypt
    def test_enc_pyAesCrypt_dec_AesCrypt(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            pyAesCrypt.encryptFile(pt, ct, password, bufferSize)
            # decrypt file
            subprocess.call(["aescrypt", "-d", "-p", password, "-o", ou, ct])
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt, ou))
            
    # test encryption with AES Crypt and decryption with pyAesCrypt
    def test_enc_AesCrypt_dec_pyAesCrypt(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            subprocess.call(["aescrypt", "-e", "-p", password, "-o", ct, pt])
            # decrypt file
            pyAesCrypt.decryptFile(ct, ou, password, bufferSize)
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt, ou))

# test binary stream functions
class TestBS(unittest.TestCase):
    # fixture for preparing the environment
    def setUp(self):
        # make directory for test files
        try:
            os.mkdir(tfdirname)
        # if directory exists, delete and re-create it
        except FileExistsError:
            # remove whole tree
            shutil.rmtree(tfdirname)
            os.mkdir(tfdirname)
        # generate a test file
        with open(filenames[4], 'wb') as fout:
            fout.write(os.urandom(2*bufferSize+19))
        
    def tearDown(self):
        # delete test files
        os.remove(filenames[4])
        os.remove(encfilenames[4])
        os.remove(decfilenames[4])
        # delete directory for test files
        os.rmdir(tfdirname)
    
    # quick test for binary stream functions
    def test_bs_quick(self):
        # encrypt
        with open(filenames[4], "rb") as fIn:
            with open(encfilenames[4], "wb") as fOut:
                pyAesCrypt.encryptStream(fIn, fOut, password, bufferSize)
        
        # get encrypted file size
        encFileSize = os.stat(encfilenames[4]).st_size
        
        # decrypt
        with open(encfilenames[4], "rb") as fIn:
            with open(decfilenames[4], "wb") as fOut:
                # decrypt file stream
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize,
                                         encFileSize)

        # check that the original file and the output file are equal
        self.assertTrue(filecmp.cmp(filenames[4], decfilenames[4]))


# test exceptions
class TestExceptions(unittest.TestCase):
    
    # test file path
    tfile = prefix + 'test.txt'
    
    # path of the copy of the test file
    tfilebak = tfile + '.bak'
    
    # fixture for preparing the environment
    def setUp(self):
        # make directory for test files
        try:
            os.mkdir(tfdirname)
        # if directory exists, delete and re-create it
        except FileExistsError:
            # remove whole tree
            shutil.rmtree(tfdirname)
            os.mkdir(tfdirname)
        # generate a test file
        with open(self.tfile, 'wb') as fout:
            fout.write(os.urandom(4))
        # copy of the test file
        shutil.copyfile(self.tfile, self.tfilebak)
        
    def tearDown(self):
        # remove whole directory tree
        shutil.rmtree(tfdirname)
    
    # test decryption with wrong password
    def test_dec_wrongpass(self):
        # encrypt file
        pyAesCrypt.encryptFile(self.tfile, self.tfile+'.aes', password,
                               bufferSize)
        # try to decrypt file using a wrong password
        # and check that ValueError is raised
        self.assertRaisesRegex(ValueError, ("Wrong password "
                                                "\(or file is corrupted\)."),
                               pyAesCrypt.decryptFile,
                               self.tfile + '.aes', self.tfile + '.decr',
                               'wrongpass', bufferSize)
                               
        # check that decrypted file was not created
        self.assertFalse(isfile(self.tfile + '.decr'))
            
    # test decryption of a non-AES-Crypt-format file
    def test_dec_not_AesCrypt_format(self):
        # encrypt file
        pyAesCrypt.encryptFile(self.tfile, self.tfile+'.aes', password,
                               bufferSize)
        # corrupt the 2nd byte (the 'E' of 'AES') - offset is 2-1=1
        corruptFile(self.tfile+'.aes', 1)
        
        # try to decrypt file
        # ...and check that ValueError is raised
        self.assertRaisesRegex(ValueError, ("File is corrupted or "
                                                "not an AES Crypt "
                                                "\(or pyAesCrypt\) file."),
                               pyAesCrypt.decryptFile,
                               self.tfile + '.aes', self.tfile + '.decr',
                               password, bufferSize)
        
        # check that decrypted file was not created
        self.assertFalse(isfile(self.tfile + '.decr'))
            
    # test decryption of an unsupported version of AES Crypt format
    def test_dec_unsupported_AesCrypt_format(self):
        # encrypt file
        pyAesCrypt.encryptFile(self.tfile, self.tfile+'.aes', password,
                               bufferSize)
        # corrupt the 4th byte
        corruptFile(self.tfile+'.aes', 3)
        
        # try to decrypt file
        # ...and check that ValueError is raised
        self.assertRaisesRegex(ValueError, ("pyAesCrypt is only "
                                                "compatible with version 2 of "
                                                "the AES Crypt file format."),
                               pyAesCrypt.decryptFile, self.tfile + '.aes',
                               self.tfile + '.decr', password, bufferSize)
                               
        # check that decrypted file was not created
        self.assertFalse(isfile(self.tfile + '.decr'))
            
    # test decryption of a file with bad hmac
    def test_dec_bad_hmac(self):
        # encrypt file
        pyAesCrypt.encryptFile(self.tfile, self.tfile+'.aes', password,
                               bufferSize)
                               
        # get file size
        fsize = os.stat(self.tfile+'.aes').st_size
        
        # corrupt hmac
        corruptFile(self.tfile+'.aes', fsize-1)
        
        # try to decrypt file
        # ...and check that ValueError is raised
        self.assertRaisesRegex(ValueError, ("Bad HMAC "
                                                "\(file is corrupted\)."),
                               pyAesCrypt.decryptFile, self.tfile + '.aes',
                               self.tfile + '.decr', password, bufferSize)
                               
        # check that decrypted file was deleted
        self.assertFalse(isfile(self.tfile + '.decr'))
            
    # test decryption of a truncated file (no complete hmac)
    def test_dec_trunc_file(self):
        # encrypt file
        pyAesCrypt.encryptFile(self.tfile, self.tfile+'.aes', password,
                               bufferSize)
                               
        # get file size
        fsize = os.stat(self.tfile+'.aes').st_size
        
        # truncate hmac (i.e.: truncate end of the file)
        with open(self.tfile+'.aes', 'r+b') as ftc:
            ftc.truncate(fsize-1)
        
        # try to decrypt file
        # ...and check that ValueError is raised
        self.assertRaisesRegex(ValueError, "File is corrupted.",
                               pyAesCrypt.decryptFile, self.tfile + '.aes',
                               self.tfile + '.decr', password, bufferSize)
                               
        # check that decrypted file was deleted
        self.assertFalse(isfile(self.tfile + '.decr'))
    
    # test same input and output file - encryption
    def test_samefile_enc(self):
        self.assertRaisesRegex(ValueError, ("Input and output files "
                                            "are the same."),
                               pyAesCrypt.encryptFile,
                               self.tfile, self.tfile,
                               'pass', bufferSize)
        # check that the original file was not modified
        self.assertTrue(filecmp.cmp(self.tfile, self.tfilebak))
    # test same input and output file - decryption
    def test_samefile_dec(self):
        self.assertRaisesRegex(ValueError, ("Input and output files "
                                            "are the same."),
                               pyAesCrypt.decryptFile,
                               self.tfile, self.tfile,
                               'pass', bufferSize)
        # check that the original file was not modified
        self.assertTrue(filecmp.cmp(self.tfile, self.tfilebak))
    
if __name__ == '__main__':
    unittest.main()
