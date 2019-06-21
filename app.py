import os
from flask import Flask, abort, request, jsonify, g, url_for, make_response
from flask_restplus import Api, Resource, fields, Namespace
from flask_cors import CORS
import datetime
from jsonschema import validate
import json

import hashlib
from nanolib import Block, generate_account_id, generate_account_private_key, get_account_id
import requests

# Environmental variables
SEED = os.environ['SEED']
REP = os.environ['REP']
API = os.environ['API']
API_KEY = os.environ['API_KEY']
# Init app 
app = Flask(__name__)
CORS(app)
api = Api(app, version='1.0', title='Nano Timestamps',
            description='Nano timestamps'
            )


# Timestamp function
def hash_to_chain(hex_dig, seed=SEED, rep=REP, api=API, api_key=API_KEY):
    account_id = generate_account_id(seed, 0)
    private_key = generate_account_private_key(seed,0)

    headers = {'Authorization': api_key}

    account = requests.post(api, json={"action": "account_info", "account":account_id}, headers=headers).json()
    new_block = Block(
         block_type="state",
         account=account_id,
         representative=rep,
         previous=account['frontier'],
         link_as_account=get_account_id(public_key=hex_dig),
         balance=int(account['balance'])-1)
    new_block.sign(private_key)
    new_block.solve_work()

    r = requests.post(api, json={"action": "process", "block": new_block.json()}, headers=headers).json()
    return r


# Namespaces
ns_stamp = Namespace('timestamp',description='Timestamp on the nano network! Input is utf-8 encoded and sha256 hashed, then sent to that nano address')
json_stamp_model = ns_stamp.schema_model('timestamp',{"$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {"target_json": {"type": "object"}},
            "required": ["target_json"],
            "additionalProperties": False})

@ns_stamp.route('/json/')
class TimeStampJson(Resource):
    @ns_stamp.doc('timestamp')
    @ns_stamp.expect(json_stamp_model)
    def post(self):
        try:
            sha_new_hash = hashlib.sha256(json.dumps(request.get_json()['target_json']).encode('utf-8')).hexdigest()
            new_hash = hash_to_chain(sha_new_hash)
        except Exception as e:
            print(e)
            return jsonify({'message': 'Failed on: {}'.format(e)})
        return jsonify({**new_hash,**{"target_json_string": json.dumps(request.get_json()['target_json'])}})

string_stamp_model = ns_stamp.schema_model('timestamp',{"$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {"target_string": {"type": "string"}},
            "required": ["target_string"],
            "additionalProperties": False})

@ns_stamp.route('/string/')
class TimeStampJson(Resource):
    @ns_stamp.doc('timestamp')
    @ns_stamp.expect(string_stamp_model)
    def post(self):
        try:
            sha_new_hash = hashlib.sha256(request.get_json()['target_string'].encode('utf-8')).hexdigest()
            new_hash = hash_to_chain(sha_new_hash)
        except Exception as e:
            print(e)
            return jsonify({'message': 'Failed on: {}'.format(e)})
        return jsonify({**new_hash,**{"target_json_string": json.dumps(request.get_json()['target_json'])}})

api.add_namespace(ns_stamp)

if __name__ == '__main__':
    app.run()


