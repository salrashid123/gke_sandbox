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
    

tink_config.register()
aead.register()
streaming_aead.register()

key_uri="gcp-kms://projects/a-demo-model/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"

gcp_client = gcpkms.GcpKmsClient(key_uri=key_uri,credentials_path="")
gcp_aead = gcp_client.get_aead(key_uri)

## streaming
keyset_handle = tink.new_keyset_handle(streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB)
streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)


env_aead = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, gcp_aead)

with open('my_model.tar.gz', 'rb') as input_file:
  with open('my_model.tar.gz.enc', 'wb') as output_file:
     with streaming_aead_primitive.new_encrypting_stream(output_file, b'aad') as enc_stream:
       for data_block in read_as_blocks(input_file):
        enc_stream.write(data_block)

stream = io.StringIO()
writer = tink.JsonKeysetWriter(stream)    
keyset_handle.write(writer, env_aead)
print(stream.getvalue())

# reader = tink.JsonKeysetReader(stream.getvalue())
# new_keyset_handle = tink.read_keyset_handle(reader, env_aead)


# with open('my_model.tar.gz.enc', 'rb') as input_file:
#   with open('my_model.tar.gz.dec', 'wb') as output_file:
#      with streaming_aead_primitive.new_decrypting_stream(input_file, b'aad') as dec_stream:
#        for data_block in read_as_blocks(dec_stream):
#         output_file.write(data_block)