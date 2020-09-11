# -*- coding: utf-8 -*-
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import io
import json
#import base64

from base64 import b64encode, b64decode

#from tabulator import topen
from sqlalchemy import create_engine
from dotenv import load_dotenv; load_dotenv('.env')
from tableschema_sql import Storage

# Will base class EncryptionDecryptionBaseEngine
from sqlalchemy_utils.types.encrypted.encrypted_type import EncryptionDecryptionBaseEngine

# Required for AWS_AES_Engine
import aws_encryption_sdk
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

# Required for AES_GCM_Engine
import six
cryptography = None
try:
    import cryptography
    from cryptography.exceptions import InvalidTag
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import (
        algorithms,
        Cipher,
        modes
    )
except ImportError:
    pass

class AWS_AES_Engine(EncryptionDecryptionBaseEngine):
    def _update_key(self, key):
        self._initialize_engine(key)

    def _initialize_engine(self, parent_class_key):
        self.secret_key = parent_class_key
        self.kms_kwargs = dict(key_ids=[self.secret_key])
        self.master_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**self.kms_kwargs)

    def _set_padding_mechanism(self, padding_mechanism=None):
        print("padding_mechanism")

    def encrypt(self, value):
        ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
            source=value,
            key_provider=self.master_key_provider
        )
        b64data = b64encode(ciphertext).decode('utf-8')
        return b64data

    def decrypt(self, value):
        decrypted_bytes, decrypted_header = aws_encryption_sdk.decrypt(
            source=b64decode(value.encode()),
            key_provider=self.master_key_provider
        )
        cycled_plaintext = decrypted_bytes.decode()
        return cycled_plaintext



class AES_GCM_Engine(EncryptionDecryptionBaseEngine):
    BLOCK_SIZE = 16
    IV_BYTES_NEEDED = 12
    TAG_SIZE_BYTES = BLOCK_SIZE

    def _initialize_engine(self, parent_class_key):
        self.secret_key = parent_class_key

    def encrypt(self, value):
        if not isinstance(value, six.string_types):
            value = repr(value)
        if isinstance(value, six.text_type):
            value = str(value)
        value = value.encode()
        iv = os.urandom(self.IV_BYTES_NEEDED)
        cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(value) + encryptor.finalize()
        assert len(encryptor.tag) == self.TAG_SIZE_BYTES
        encrypted = b64encode(iv + encryptor.tag + encrypted)
        return encrypted.decode('utf-8')

    def decrypt(self, value):
        if isinstance(value, six.text_type):
            value = str(value)
        decrypted = b64decode(value)
        if len(decrypted) < self.IV_BYTES_NEEDED + self.TAG_SIZE_BYTES:
            raise InvalidCiphertextError()
        iv = decrypted[:self.IV_BYTES_NEEDED]
        tag = decrypted[self.IV_BYTES_NEEDED:
                        self.IV_BYTES_NEEDED + self.TAG_SIZE_BYTES]
        decrypted = decrypted[self.IV_BYTES_NEEDED + self.TAG_SIZE_BYTES:]
        cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        try:
            decrypted = decryptor.update(decrypted) + decryptor.finalize()
        except InvalidTag:
            raise InvalidCiphertextError()
        if not isinstance(decrypted, six.string_types):
            try:
                decrypted = decrypted.decode('utf-8')
            except UnicodeDecodeError:
                raise InvalidCiphertextError()
        return decrypted

print(AWS_AES_Engine)
print(AES_GCM_Engine)

# Engine
engine = create_engine('postgresql://postgres:postgres@localhost:5432/postgres')

# Storage
storage = Storage(engine=engine, prefix='')

# Define encryption options
'''
encryptedDefintion = {
    "ssn": {
        "key": "",
        "engine": AWS_AES_Engine
    }
}
'''
encryptedDefintion = {
    "ssn": {
        "key": "G8Zkf^94Ra505tHliIxAMZy9GJObEyF1",
        "engine": AES_GCM_Engine
    }
}

# Create tables
records_schema = """
{
    "primaryKey": "id",
    "fields": [
        {
            "name": "id",
            "type": "integer",
            "constraints": {
                "required": true
            }
        },
        {
            "name": "name",
            "type": "string"
        },
        {
            "name": "ssn",
            "type": "string",
            "encrypted": true
        }
    ]
}
"""

storage.create(['records'], [json.loads(records_schema)], encrypted_definitions=encryptedDefintion)

records_data = [
    [ 1, "John", "123456789" ]
]

storage.write('records', records_data)

print(storage.describe('records'))

print(list(storage.read('records')))
