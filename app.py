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

def validate_block(block,message,api=API,api_key=API_KEY):
    headers = {'Authorization': api_key}
    info = requests.post(api, json={"action": "block_info", "hash":block}, headers=headers).json()
    contents = json.loads(info['contents'])
    encoded = hashlib.sha256(message.encode('utf-8')).hexdigest().upper()
    if contents['link'].upper() == encoded:
        return {'valid':True}
    else:
        return {'valid':False}

# Namespaces
ns_stamp = Namespace('timestamp',description='Timestamp on the nano network! Input is utf-8 encoded and sha256 hashed, then sent to that nano address')
json_stamp_model = ns_stamp.schema_model('json_timestamp',{"$schema": "http://json-schema.org/schema#",
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

string_stamp_model = ns_stamp.schema_model('string_timestamp',{"$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {"target_string": {"type": "string"}},
            "required": ["target_string"],
            "additionalProperties": False})

@ns_stamp.route('/string/')
class TimeStampJson(Resource):
    @ns_stamp.doc('timestamp')
    @ns_stamp.expect(string_stamp_model)
    def post(self):
        target_string = request.get_json()['target_string']
        try:
            sha_new_hash = hashlib.sha256(target_string.encode('utf-8')).hexdigest()
            new_hash = hash_to_chain(sha_new_hash)
        except Exception as e:
            print(e)
            return jsonify({'message': 'Failed on: {}'.format(e)})
        return jsonify({**new_hash,**{"target_string": target_string}})

ns_validate = Namespace('validate',description='Validate a block on the blockchain')
validate_schema = {"$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {"message": {"type": "string"},
                "block": {"type": "string"}
                },
            "required": ["message","block"],
            "additionalProperties": False}
validate_model = ns_validate.schema_model('string_validate',validate_schema)

@ns_validate.route('/')
class ValidateBlock(Resource):
    @ns_validate.doc('validate_basic')
    @ns_validate.expect(validate_model)
    def post(self):
        obj = request.get_json()
        try:
            validate(instance=obj,schema=validate_schema)
        except Exception as e:
            return make_response(jsonify({'message': 'Failed on: {}'.format(e)}),422)
        return jsonify(validate_block(obj['block'],obj['message']))

api.add_namespace(ns_stamp)
api.add_namespace(ns_validate)
if __name__ == '__main__':
    app.run()


