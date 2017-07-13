#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import re
import time
import hashlib
import hmac
import urllib.parse
import requests
import json
import sys
import copy

oauth_consumer_key     = 'k0AGtDrE0ovNTiwjYExgLnyNr'
oauth_consumer_secret  = '9ru0jWTE6Pta1aqla9BVrySPtlrindboTH0UGyioS8EdRDuYq6'
oauth_callback         = 'oob'
oauth_signature_method = 'HMAC-SHA1'
oauth_version          = '1.0'

oauth_token = ''
oauth_token_secret = ''

confdir           = os.environ['HOME'] + '/.sheilld'
path_token        = confdir + '/oauth_token'
path_token_secret = confdir + '/oauth_token_secret'

def hmac_sha1(key, msg):
	# Reference: https://gist.github.com/heskyji/5167567b64cb92a910a3
	digester = hmac.new(bytes(key, 'UTF-8'), bytes(msg, 'UTF-8'), hashlib.sha1)
	sign1 = digester.digest()
	sign2 = base64.b64encode(sign1)
	return str(sign2, 'UTF-8')

def percent_encode(src):
	dst = ''
	reserved = re.compile('[A-Za-z0-9-._~]')
	for char in src:
		if reserved.search(char):
			dst += char
		else:
			dst += '%'+format(ord(char), 'x').upper()
	return dst

def gen_oauth_nonce():
	random  = os.urandom(32)
	encoded = base64.b64encode(random)
	words   = re.sub('[^\w]', '', str(encoded))
	return words

def gen_oauth_timestamp():
	return int(time.time())

def build_signature(method, url, oauth_params, params={}):
	all_params = copy.deepcopy(oauth_params)
	all_params.update(params)
	keys = sorted(all_params.keys())
	encoded_params = ''
	for key in keys:
		encoded_params += key+'='+percent_encode(str(all_params[key]))+'&'
	encoded_params = encoded_params[:-1]
	base_string = method.upper()+'&'+percent_encode(url)+'&'+percent_encode(encoded_params)
	signing_key = oauth_consumer_secret+'&'+oauth_token_secret
	return hmac_sha1(signing_key, base_string)

def build_oauth_header(params):
	header = 'OAuth '
	for key, val in params.items():
		header += key+'="'+str(val)+'", '
	return header[:-2]

def post(url, params):
	# Generate temporaly-used parameters
	oauth_nonce     = gen_oauth_nonce()
	oauth_timestamp = gen_oauth_timestamp()
	oauth_params = {
		'oauth_token'            : oauth_token,
		'oauth_consumer_key'     : oauth_consumer_key,
		'oauth_signature_method' : oauth_signature_method,
		'oauth_version'          : oauth_version,
		'oauth_nonce'            : oauth_nonce,
		'oauth_timestamp'        : oauth_timestamp,
	}
	oauth_signature =  build_signature('POST', url, oauth_params, params=params)
	oauth_params['oauth_signature'] = percent_encode(str(oauth_signature))
	for key, val in params.items():
		params[key] = str(val)#percent_encode(str(val))
	request = requests.post(url, params, headers={'Authorization': build_oauth_header(oauth_params)})
	return request

def register():
	global oauth_token, oauth_token_secret
	request_token_url = 'https://api.twitter.com/oauth/request_token'
	oauth_nonce     = gen_oauth_nonce()
	oauth_timestamp = gen_oauth_timestamp()
	oauth_params = {
		'oauth_consumer_key'     : oauth_consumer_key,
		'oauth_callback'         : oauth_callback,
		'oauth_signature_method' : oauth_signature_method,
		'oauth_version'          : oauth_version,
		'oauth_nonce'            : oauth_nonce,
		'oauth_timestamp'        : oauth_timestamp
	}
	# Build signature
	oauth_signature =  build_signature('POST', request_token_url, oauth_params)
	oauth_params['oauth_signature'] = percent_encode(str(oauth_signature))
	# Connect
	request = requests.post(request_token_url, '', headers={'Authorization': build_oauth_header(oauth_params)})
	if request.status_code == 200:
		data = urllib.parse.parse_qs(request.text)
		oauth_token        = data['oauth_token'][0]
		oauth_token_secret = data['oauth_token_secret'][0]
		print('https://api.twitter.com/oauth/authorize?oauth_token='+oauth_token)
		pin = input('pin:')
		access_token_url = 'https://api.twitter.com/oauth/access_token'
		request = post(access_token_url, {'oauth_verifier' : pin})
		data = urllib.parse.parse_qs(request.text)
		oauth_token        = data['oauth_token'][0]
		oauth_token_secret = data['oauth_token_secret'][0]
		if not os.path.exists(confdir):
			os.makedirs(confdir)
		f = open(path_token, 'w+')
		oauth_token = f.write(oauth_token)
		f.close()
		f = open(path_token_secret, 'w+')
		oauth_token = f.write(oauth_token_secret)
		f.close()

if os.path.exists(path_token):
	f = open(path_token, 'r')
	oauth_token = f.read()
	f.close()
if os.path.exists(path_token_secret):
	f = open(path_token_secret, 'r')
	oauth_token_secret = f.read()
	f.close()

if (oauth_token == '') | (oauth_token_secret == ''):
	register()

