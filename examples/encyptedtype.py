# -*- coding: utf-8 -*-
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import io
import json

from sqlalchemy import create_engine
from tableschema_sql import Storage
from tableschema_sql.crypto import AES_GCM_Engine, AWS_AES_Engine

# Engine
engine = create_engine('postgresql://postgres:postgres@localhost:5432/postgres')

# Storage
storage = Storage(engine=engine, prefix='')

# Define encryption options
encryptedDefintion = {
    "records": {
        "*": {
            "key": "G8Zkf^94Ra505tHliIxAMZy9GJObEyF1",
            "engine": AES_GCM_Engine
        }
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
            "protected": true
        }
    ]
}
"""

storage.create(['records'], [json.loads(records_schema)], encrypted_definitions=encryptedDefintion)

records_data = [
    [ 1, "John", "123456789"]
]

storage.write('records', records_data)

print(storage.describe('records'))

print(list(storage.read('records')))
