#!/usr/bin/python


import base64
import io
import tink
from tink import aead
from tink import tink_config
from tink import mac
from tink.proto import tink_pb2
from tink.proto import common_pb2
from tink.integration import gcpkms
from tink import core

from tink import secret_key_access
from tink import streaming_aead
from tink import cleartext_keyset_handle

from typing import BinaryIO
from absl import logging


# https://developers.google.com/tink/encrypt-large-files-or-data-streams

BLOCK_SIZE = 1024 * 1024  # The CLI tool will read/write at most 1 MB at once.

def read_as_blocks(file: BinaryIO):
  while True:
    data = file.read(BLOCK_SIZE)
    if data == b'':
      break
    yield data
    
key= """{
  "encryptedKeyset": "AAAAcwokAJ7xtzA7UOT/m/YaY0YjOVPFfMPANnKuBnx6zgh5/zWYZM10EksAtyrKgAE1T052/mT50ueKXDfJVUEVTujlL0aep6YXdXgeDUqRQL/cONHVTM7SkHUShu3WPMkbtiylEpxF6CK4Z8cmosxzd5NM5uJIyG36loLBXgAK1asHznL3gY+kPHCwor+Fm8gx0nadURKXOx3x8VjDyz8uHcgCn1Y4AvxlaS4chxMEZksQZUaw5IPnmKVQEM6XkO/EKRI/amwsRWr5Y7/K1/yrYSt7Aev7UlbyEmhPtxwWOjo8EenLDpAPOGVksENYmJwRhOYicNSrubnNnZdHqRL/UkjFJYeVvN5uejVETeR178HTyRv8q3/4YHQ=",
  "keysetInfo": {
    "primaryKeyId": 471357398,
    "keyInfo": [
      {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
        "status": "ENABLED",
        "keyId": 471357398,
        "outputPrefixType": "RAW"
      }
    ]
  }
}"""


tink_config.register()
aead.register()
streaming_aead.register()

key_uri="gcp-kms://projects/a-demo-model/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"

gcp_client = gcpkms.GcpKmsClient(key_uri=key_uri,credentials_path="")
gcp_aead = gcp_client.get_aead(key_uri)

env_aead = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, gcp_aead)


stream = io.StringIO(key) 
reader = tink.JsonKeysetReader(stream.getvalue())
keyset_handle = tink.read_keyset_handle(reader, env_aead)
new_streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
print(stream.getvalue())

streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

with open('my_model.tar.gz.enc', 'rb') as input_file:
  with open('my_model.tar.gz.dec', 'wb') as output_file:
     with streaming_aead_primitive.new_decrypting_stream(input_file, b'aad') as dec_stream:
       for data_block in read_as_blocks(dec_stream):
        output_file.write(data_block)