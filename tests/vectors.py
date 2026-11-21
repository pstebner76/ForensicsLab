"""Ground truth the tests are not allowed to "fix" by copying program output.

The empty-input and ``abc`` digests are published hash test vectors. The
long-buffer digests were produced by hashlib's one-shot hash of the whole
buffer, then frozen here, so a chunking bug cannot agree with itself.

If a test fails on these values, fix the hasher. Do not paste a new digest
over a constant to make the test pass.
"""

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# ASCII b"abc", with no trailing newline. A newline is a different file.
ABC = b"abc"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"
ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

# 9000 bytes, which is more than the 8192-byte read buffer.
LONG_PAYLOAD = b"abc" * 3000
LONG_MD5 = "f361a8b5d3cdb3477d7eece65b0fb280"
LONG_SHA1 = "ce5da373b59d644a1fd05e605479750460ae640f"
LONG_SHA256 = "fc6e41e7e4d627792fa57bd240e8263e5cb151f878e0175a867891f5ce630b1b"
