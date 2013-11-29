# -*- coding: utf-8 -*-

"""a new module wrapping around M2Crypto to do ECC specific stuffs
Written by Tony Cheneau"""

from __future__ import with_statement
from subprocess import PIPE, Popen
from copy import deepcopy
import sys
import hashlib

try:
    from M2Crypto import EC, BIO
except ImportError:
    print "unable to import M2Crypto, please install it to your system"
    print "ECC library disabled"
    raise ImportError





# copy the PEM from the M2Cryto file
NID = [ nid for nid in dir(EC) if "NID_sec" in nid  ]
for curve in NID:
    setattr(sys.modules[__name__], curve, getattr(EC, curve))

def openssl_call(cmd, stdin):
    """pass a call to the openssl library"""
    p = Popen( ["openssl"] + cmd , bufsize=4096, stdin = PIPE, stdout = PIPE, stderr = PIPE) 


    p.stdin.write(stdin)
    p.stdin.close()

    return p.stdout.read()

def test_ECC():
    """unitary test for this module.
    Run "nosetests --all-modules" in the directory that contains this file"""

    # create a new key
    key = ECCkey(NID_secp384r1)

    # export it to PEM format
    pem_encoded = key.to_PEM()

    # create a new key for the first key's PEM encoded data
    key2 = ECCkey()
    key2.from_PEM(pem_encoded)

    # create a third key from an object of type ECCkey
    key3 = ECCkey(key2)

    # loading a PEM private key
    assert ECCkey(pem_encoded).to_PEM() == pem_encoded

    # export the two keys' Public Key and compare them
    pubder1 = key.PubKey_to_DER()
    pubder2 = key2.PubKey_to_DER()
    pubder3 = key3.PubKey_to_DER()

    assert pubder1 == pubder2 == pubder3

    # loading a DER encoded public key
    assert ECCkey(pubder1).PubKey_to_DER() == pubder2

    # loading a PEM encoded public key
    pubpem1 = ECCkey(pubder1).PubKey_to_PEM()
    assert ECCkey(pubpem1).PubKey_to_PEM() == pubpem1



    # signs some data and verify the signature
    signature = key.sign("data")
    assert key.verify("data", signature) == 1

    # verify that the signature indeed correspond to that message
    assert key.verify("duta", signature) == 0

    # reload the pubkey inside a new key
    key3 = ECCkey()
    key3.PubKey_from_DER(pubder1)
    assert key3.verify("data", signature) == 1

    # a wrong signature is, of course, not valid
    signature = chr(ord(signature[0])+1) + signature[1:]
    assert key.verify("data", signature) == -1

    assert ECCkey(NID_secp256k1).get_sigtypeID() == [ 9 ]
    assert ECCkey(NID_secp384r1).get_sigtypeID() == [ 10 ]
    assert ECCkey(NID_secp521r1).get_sigtypeID() == [ 11 ]

class ECCException(Exception):
    """an exception class for this EC module"""
    pass


class ECCkey(object):
    """an EC key object"""

    def __init__(self, nid_or_path = None):
        """nid_or_path is either a nid to create a new key or a path to a pem encoded key"""

        self._key = None

        # we don't have anything to initialize anymore
        if type(nid_or_path) == type(None):
            return # do nothing
        elif type(nid_or_path) == int:
            self._key = EC.gen_params(nid_or_path)
            self._key.gen_key()
        elif type(nid_or_path) == str:
            # the string is a DER public key ?
            # OID == 1.2.840.10045.2.1
            # encoder.encode(univ.ObjectIdentifier("1.2.840.10045.2.1"))
            if nid_or_path.startswith("\x30") and \
                    "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" in nid_or_path:
                self.PubKey_from_DER(nid_or_path)

            # the string is a PEM key ?
            elif "-----BEGIN EC PRIVATE KEY-----" in nid_or_path:
                self.from_PEM(nid_or_path)
            elif "-----BEGIN PUBLIC KEY-----" in nid_or_path:
                self.PubKey_from_PEM(nid_or_path)

            else:
                # the string is a path ?
                with open(nid_or_path) as f:
                    self.from_PEM(f.read())

        elif isinstance(nid_or_path, ECCkey):
            self.from_PEM(nid_or_path.to_PEM())
        else:
            raise ECCException("ECCkey should be instanciated py a NID number or a path to a valid EC key""")

    def get_sigtypeID(self):
        """return the signature type ID (as define in draft-cheneau-csi-send-sig-agility-01)
        if the curve allows it, or return None"""

        # OID of secp256k1 curve: 1.3.132.0.10
        # OID of secp384r1 curve: 1.3.132.0.34
        # OID of secp521r1 curve: 1.3.132.0.35 

        # I converted these OIDs to octet-string with
        # pyasn1:
        # encoder.encode(univ.ObjectIdentifier('1.3.132.0.10'))
        
        #  1.3.132.0.10 -> "\x06\x05\x2B\x81\x04\x00\x0a"
        #  1.3.132.0.34 −> "\x06\x05\x2B\x81\x04\x00\x22"
        #  1.3.132.0.35 -> "\x06\x05\x2B\x81\x04\x00\x23"

        if "\x06\x05\x2B\x81\x04\x00\x0a" in str(self):
            return [ 9 ] # P-256
        elif "\x06\x05\x2B\x81\x04\x00\x22" in str(self):
            return [ 10 ]# P-384
        elif "\x06\x05\x2B\x81\x04\x00\x23" in str(self):
            return [ 11 ] # P-512

        return None


    def to_PEM(self):
        """convert the internal key to a PEM encoded string"""
        m = BIO.MemoryBuffer()
        self._key.save_key_bio(m, None)
        return m.read_all()

    def from_PEM(self, pemkey):
        """import a EC key from a PEM encoded string"""
        m = BIO.MemoryBuffer(pemkey)
        self._key = EC.load_key_bio(m)

    def PubKey_to_PEM(self):
        """convert the internal public key to a PEM encoded string"""
        m = BIO.MemoryBuffer()
        self._key.save_pub_key_bio(m)
        return m.read_all()

    def PubKey_from_PEM(self, pemkey):
        m = BIO.MemoryBuffer(pemkey)
        self._key = EC.load_pub_key_bio(m)


    def PubKey_to_DER(self):
        """convert the internal representation of the Public Key into a DER encoded Public Key"""
        pem_key = self.PubKey_to_PEM()

        return openssl_call(["ec", "-pubout","-outform","DER", "-pubin"],pem_key)

    def PubKey_from_DER(self,der_pkey):
        pem_pkey = openssl_call(["ec", "-pubin","-inform","DER","-pubout","-outform","PEM"],der_pkey)
        self.PubKey_from_PEM(pem_pkey)
        

    def sign(self, message, t=None, h="sha256", mgf=None, sLen=None):
        """signs a message with an DER encoded ECDSA signature
        (have an interchangeable interface with cert.py)"""
        if h == "sha1":
            print "sha1 should not be use with this module"
            return
        elif h == "sha256":
            digest = hashlib.sha256(message).digest()
        elif h == "sha384":
            digest = hashlib.sha384(message).digest()
        elif h == "sha512":
            digest = hashlib.sha512(message).digest()
        else:
            print "correct values for the hash function are sha256, sha384, sha512"
            return

        return self._key.sign_dsa_asn1(digest)

    def verify(self, message, signature, t=None, h="sha256", mgf=None, sLen=None):
        """verifies an ECDSA signature
        (return True, False or -1 on error)
        (have an interchangeable interface with cert.py)"""

        if h == "sha1":
            print "sha1 should not be use with this module"
            return
        elif h == "sha256":
            digest = hashlib.sha256(message).digest()
        elif h == "sha384":
            digest = hashlib.sha384(message).digest()
        elif h == "sha512":
            digest = hashlib.sha512(message).digest()
        else:
            print "correct values for the hash function are sha256, sha384, sha512"
            return -1

        try:
            return self._key.verify_dsa_asn1(digest, signature) == 1
        except EC.ECError:
            return -1

    def __getattr__(self, name):
        """function used to emulate the behavior of PubKey()"""
        if name == "derkey":
            return self.PubKey_to_DER()
        elif name == "pemkey":
            return self.PubKey_to_PEM()
        else:
            raise AttributeError

    def __str__(self):
        """return the DER encoded Public Key"""

        return self.PubKey_to_DER()
