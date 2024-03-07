from flask import Flask, render_template, request, abort,  send_from_directory, jsonify

from google.cloud import storage

import io
import base64
import time, logging, threading
import tink
from tink import aead
from tink import tink_config

from tink.integration import gcpkms

from tink import streaming_aead
from typing import BinaryIO
import tarfile
import tensorflow as tf

from waitress import serve

import argparse
 
app = Flask(__name__)

import_model = None
download_status = False
decrypt_status = False 
model_verified = False

bucket_name = ''
blob_name = ''
key_uri = ''

@app.route('/public/<path:path>')
def send_report(path):
    return send_from_directory('public', path)

@app.route('/predict', methods=['POST'])
def predict():
  try:
    review =  request.get_json()
    return jsonify(import_model.predict(review["reviews"]).tolist())  
  except Exception as e:
    logging.error("Error: " + str(e))
    abort(500)


@app.route('/check', methods=['GET'])
def check():
  global import_model
  global download_status
  global decrypt_status 
  global model_verified
  try:
    data = { 
        "downloaded" : download_status, 
        "decrypted" : decrypt_status, 
        "model_verified" : model_verified,         
    } 
  
    return jsonify(data) 

  except Exception as e:
    print("Error: " + str(e))
    abort(500)


@app.route('/', methods=['GET'])
def index():
  try:
    return render_template('index.html')
  except Exception as e:
    logging.error("Error: " + str(e))
    abort(500)

@app.errorhandler(500)
def server_error(e):
  logging.exception('An error occurred during a request.')
  return 'An internal error occurred.', 500

BLOCK_SIZE = 1024 * 1024  # The CLI tool will read/write at most 1 MB at once.

def read_as_blocks(file: BinaryIO):
  while True:
    data = file.read(BLOCK_SIZE)
    if data == b'':
      break
    yield data

def thread_function(name):
    global import_model
    global download_status
    global decrypt_status 
    global model_verified    
    while True:
      try:

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        blob = bucket.get_blob(blob_name)
        key_encoded = blob.metadata.get('encryption-key')

        key_b64 = base64.b64decode(key_encoded)
        key = key_b64.decode('utf-8')

      # key= """{
      #   "encryptedKeyset": "AAAAcwokAJ7xtzA7UOT/m/YaY0YjOVPFfMPANnKuBnx6zgh5/zWYZM10EksAtyrKgAE1T052/mT50ueKXDfJVUEVTujlL0aep6YXdXgeDUqRQL/cONHVTM7SkHUShu3WPMkbtiylEpxF6CK4Z8cmosxzd5NM5uJIyG36loLBXgAK1asHznL3gY+kPHCwor+Fm8gx0nadURKXOx3x8VjDyz8uHcgCn1Y4AvxlaS4chxMEZksQZUaw5IPnmKVQEM6XkO/EKRI/amwsRWr5Y7/K1/yrYSt7Aev7UlbyEmhPtxwWOjo8EenLDpAPOGVksENYmJwRhOYicNSrubnNnZdHqRL/UkjFJYeVvN5uejVETeR178HTyRv8q3/4YHQ=",
      #   "keysetInfo": {
      #     "primaryKeyId": 471357398,
      #     "keyInfo": [
      #       {
      #         "typeUrl": "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
      #         "status": "ENABLED",
      #         "keyId": 471357398,
      #         "outputPrefixType": "RAW"
      #       }
      #     ]
      #   }
      # }"""


        tink_config.register()
        aead.register()
        streaming_aead.register()

        

        gcp_client = gcpkms.GcpKmsClient(key_uri=key_uri,credentials_path="")
        gcp_aead = gcp_client.get_aead(key_uri)

        env_aead = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, gcp_aead)

        stream = io.StringIO(key) 
        reader = tink.JsonKeysetReader(stream.getvalue())
        keyset_handle = tink.read_keyset_handle(reader, env_aead)
        print(stream.getvalue())

        streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)


        with blob.open('rb') as input_file:
            with streaming_aead_primitive.new_decrypting_stream(input_file, b'aad') as dec_stream:
              # don't know if its possible to stream untar in chunks...
              concatenated_bytes = b''
              for data_block in read_as_blocks(dec_stream):
                download_status = True


                concatenated_bytes = concatenated_bytes + data_block
              decrypt_status = True 
              with tarfile.open(fileobj=io.BytesIO(concatenated_bytes)) as so:
                so.extractall(path='.')

        model_version = "1"
        path = 'my_model/' + model_version
        ### Load the model from disk
        import_model = tf.keras.models.load_model(path)

        examples = [
          "The movie was great!",
          "The movie was okay.",
          "The movie was terrible...",
          "awesome"
        ]
        print(import_model.predict(examples))
        model_verified = True
        break
      except Exception as err:
        print(err)
      time.sleep(10)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  
  parser.add_argument("bucket", help = "Bucket", default ='a-demo-model-bucket' )
  parser.add_argument("object", help = "Object", default = 'my_model.tar.gz.enc')
  parser.add_argument("key", help = "Key", default = 'gcp-kms://projects/a-demo-model/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1')
  
  args = parser.parse_args()
  
  bucket_name = args.bucket
  blob_name = args.object
  key_uri= args.key
    
  print(tf.version.VERSION)

  x = threading.Thread(target=thread_function, args=(1,))
  x.start()
  serve(app, host="0.0.0.0", port=8080)
