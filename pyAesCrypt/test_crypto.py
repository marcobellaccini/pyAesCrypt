#==============================================================================
# Copyright 2016 Marco Bellaccini - marco.bellaccini[at!]gmail.com
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
filenames = [prefix+'empty', prefix+'block', prefix+'defbuffer', prefix+'small', prefix+'med', prefix+'tbuf']

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

# generate test files
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
        
# tests encryption and decryption
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
            self.assertTrue(filecmp.cmp(pt,ou))
            
    # test encryption with pyAesCrypt and decryption with AES Crypt
    def test_enc_pyAesCrypt_dec_AesCrypt(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            pyAesCrypt.encryptFile(pt, ct, password, bufferSize)
            # decrypt file
            subprocess.call(["aescrypt", "-d", "-p", password, "-o", ou, ct])
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt,ou))
            
    # test encryption with AES Crypt and decryption with pyAesCrypt
    def test_enc_AesCrypt_dec_pyAesCrypt(self):
        for pt, ct, ou in zip(filenames, encfilenames, decfilenames):
            # encrypt file
            subprocess.call(["aescrypt", "-e", "-p", password, "-o", ct, pt])
            # decrypt file
            pyAesCrypt.decryptFile(ct, ou, password, bufferSize)
            # check that the original file and the output file are equal
            self.assertTrue(filecmp.cmp(pt,ou))

if __name__ == '__main__':
    unittest.main()
    