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
API_KEY = os.environ['API_KEY']
PASSWORD = os.environ['PASSWORD']
ADDRESS = os.environ['ADDRESS']
headers = {'x-api-key': API_KEY}
# Init app 
app = Flask(__name__)
CORS(app)
api = Api(app, version='1.0', title='Nano Timestamps',
            description='Nano timestamps'
            )


def get_public_account(msg:bytes):
    return get_account_id(public_key=hashlib.sha256(msg).hexdigest())

# Namespaces
ns_stamp = Namespace('timestamp',description='Timestamp on the nano network! Input is utf-8 encoded and sha256 hashed, then sent to that nano address')
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
            target_account = get_public_account(target_string.encode('utf-8'))
            r = requests.post('https://snapy.io/api/v1/send',headers=headers,json={'to':target_account,'from':ADDRESS,'amount':1,'password':PASSWORD})
            if r.json()['status'] != 'success':
                raise ValueError('Failed transfer')            
        except Exception as e:
            print(e)
            return make_response(jsonify({'message': 'Failed on: {}'.format(e)}),400)
        return jsonify({"target_string": target_string, "hash": r.json()["hash"], "target_account":target_account})

#ns_validate = Namespace('validate',description='Validate a block on the blockchain')
#validate_schema = {"$schema": "http://json-schema.org/schema#",
#            "type": "object",
#            "properties": {"message": {"type": "string"},
#                "block": {"type": "string"}
#                },
#            "required": ["message","block"],
#            "additionalProperties": False}
#validate_model = ns_validate.schema_model('string_validate',validate_schema)
#
#@ns_validate.route('/')
#class ValidateBlock(Resource):
#    @ns_validate.doc('validate_basic')
#    @ns_validate.expect(validate_model)
#    def post(self):
#        obj = request.get_json()
#        try:
#            validate(instance=obj,schema=validate_schema)
#        except Exception as e:
#            return make_response(jsonify({'message': 'Failed on: {}'.format(e)}),422)
#        return jsonify(validate_block(obj['block'],obj['message']))
#
api.add_namespace(ns_stamp)
#api.add_namespace(ns_validate)
if __name__ == '__main__':
    app.run()


