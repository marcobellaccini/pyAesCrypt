History
==================

6.0.0 (May 2021)
~~~~~~~~~~~~~~~~~~
* Updated password complexity check
* Set a default buffer size

5.0.0 (Gen 2021)
~~~~~~~~~~~~~~~~~~
* Fixed misleading messages when IOErrors occur (some public API exceptions where changed)
* Switched to Semantic Versioning

0.4.4 (Dec 2020)
~~~~~~~~~~~~~~~~~~
* Improved decryption speed
* Cross-platform CI

0.4.3 (Apr 2019)
~~~~~~~~~~~~~~~~~~
* Fixed bug when deleting bad output file (this was unnoticeable when running on GNU/Linux)

0.4.2 (Sep 2018)
~~~~~~~~~~~~~~~~~~
* Fixed bug when handling same input and output file 

0.4.1 (Sep 2018)
~~~~~~~~~~~~~~~~~~
* Preventing users from specifying the same input and output file 

0.4 (Aug 2018)
~~~~~~~~~~~~~~~~~~
* Support for binary stream encryption/decryption

0.3.1 (May 2018)
~~~~~~~~~~~~~~~~~~
* Fixed Python version compatibility classifier
* Removed useless stat

0.3 (Aug 2017)
~~~~~~~~~~~~~~~~~~
* Switched from `pycrypto`_ to `PyCA Cryptography`_ for crypto primitives
* Unittests clean-up

0.2.2 (Aug 2017)
~~~~~~~~~~~~~~~~~~
* Option to pass password as command-line argument to the script

0.2.1 (Feb 2017)
~~~~~~~~~~~~~~~~~~
* Better exceptions handling
* Code clean-up
* More unittests

0.2 (Jan 2017)
~~~~~~~~~~~~~~~~~~
* Modularized pyAesCrypt (and now the script calls the module for operations)
* Improved decryption speed (patch by Ben Fisher, see THANKS.rst)
* Improved encryption speed too
* Unittests
* Travis-CI integration
* Uploaded project to GitHub

0.1.2 (Jan 2016)
~~~~~~~~~~~~~~~~~~
* Bugfix

0.1 (Jan 2016)
~~~~~~~~~~~~~~~~~~
* First public release

.. _pycrypto: https://github.com/dlitz/pycrypto
.. _PyCA Cryptography: https://github.com/pyca/cryptography
