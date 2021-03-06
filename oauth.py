#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OAuth Package for Shielld
"""

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
import shutil

oauth_consumer_key     = 'AmPvijYirICwMaD773FHcdODu'
oauth_callback         = 'oob'
oauth_signature_method = 'HMAC-SHA1'
oauth_version          = '1.0'

user_name = ''
users     = {}

conf_dir   = os.environ['HOME'] + '/.shielld'
users_dir  = conf_dir + '/users'
conf_files = {
	'oauth_token',
	'oauth_token_secret',
	'user_id'
}

mute_ids = []

def hmac_sha1(key, msg):
	'''
	Calculate HMAC-SHA1 to create signature
	Reference: https://gist.github.com/heskyji/5167567b64cb92a910a3
	'''
	digester = hmac.new(bytes(key, 'UTF-8'), bytes(msg, 'UTF-8'), hashlib.sha1)
	sign1 = digester.digest()
	sign2 = base64.b64encode(sign1)
	return str(sign2, 'UTF-8')

def percent_encode(src):
	"""
	URL encoding based on RFC3986
	https://tools.ietf.org/html/rfc3986#section-2.1
	"""
	dst = ''
	reserved = re.compile('[A-Za-z0-9-._~]')
	for char in src:
		if reserved.search(char):
			dst += char
		else:
			# Percent encode needed chars
			# Convert each byte to hex
			for byte in list(char.encode('UTF-8')):
				if reserved.search(chr(byte)):
					dst += chr(byte)
				else:
					dst += '%'+hex(byte)[2:].upper()
	return dst

def gen_oauth_nonce():
	"""
	Generate oauth nonce for Twiter API
	- Get random 32 bytes data
	- Base64 encode
	- Pick only word characters
	"""
	random  = os.urandom(32)
	encoded = base64.b64encode(random)
	words   = re.sub('[^\w]', '', str(encoded))
	return words

def gen_oauth_timestamp():
	"""
	Get current timestamp as integer
	"""
	return int(time.time())

def build_signature(method, url, oauth_params, params={}):
	"""
	Create OAuth signature for Twitter API
	crypt base : ${method}&${url}&${sorted_params}
	crypt key  : ${consumer_secret}&${oauth_token_secret}
	"""
	# Copy params to prevent modification from original params
	all_params = copy.deepcopy(oauth_params)
	# Combine OAuth parameters and original parameters
	all_params.update(params)
	# Sort, stringify, and encode all parameters
	keys = sorted(all_params.keys())
	encoded_params = ''
	for key in keys:
		encoded_params += key+'='+percent_encode(str(all_params[key]))+'&'
	encoded_params = encoded_params[:-1]
	base_string = method.upper()+'&'+percent_encode(url)+'&'+percent_encode(encoded_params)
	# Request crypt calculation to the server and return caluculated value
	calc_url = 'https://www.ryotosaito.com/shielld/calc_signature.php'
	oauth_token_secret = users[user_name]['oauth_token_secret'] if user_name in users else ''
	params = {'base_string' : base_string, 'oauth_token_secret' : oauth_token_secret}
	request = requests.post(calc_url, params);
	return request.text

def build_oauth_header(params):
	"""
	Create OAuth header
	Authorization: OAuth key=val, key=val, ...
	"""
	header = 'OAuth '
	for key, val in params.items():
		header += key+'="'+str(val)+'", '
	return header[:-2]

def connect(method, url, params, stream=False):
	"""
	Request server with specified arguments
	"""
	# Generate temporaly-used parameters
	oauth_nonce     = gen_oauth_nonce()
	oauth_timestamp = gen_oauth_timestamp()
	oauth_params = {
		'oauth_token'            : users[user_name]['oauth_token'] if user_name != '' else oauth_token,
		'oauth_consumer_key'     : oauth_consumer_key,
		'oauth_signature_method' : oauth_signature_method,
		'oauth_version'          : oauth_version,
		'oauth_nonce'            : oauth_nonce,
		'oauth_timestamp'        : oauth_timestamp,
	}
	oauth_signature =  eval('build_signature("' + method.upper() + '", url, oauth_params, params=params)')
	oauth_params['oauth_signature'] = percent_encode(oauth_signature)
	for key, val in params.items():
		params[key] = str(val)
	request = eval('requests.' + method + '(url, params, stream=stream, headers={"Authorization": build_oauth_header(oauth_params)})')
	return request

def get(url, params={}):
	return connect('get', url, params)

def post(url, params={}):
	return connect('post', url, params)

def stream(url, params={}):
	return connect('get', url, params, stream=True)

def getstream():
	url = 'https://userstream.twitter.com/1.1/user.json'
	params = {'with' : 'followings'}
	with stream(url, params) as r:
		for line in r.iter_lines():
			if line:
				decoded_line = line.decode('utf-8')
				tweet_data = json.loads(decoded_line)
				if 'text' in tweet_data and tweet_data['user']['id'] not in mute_ids:
					print(tweet_data['user']['name']+'(@'+tweet_data['user']['screen_name']+')')
					print(tweet_data['text'])

def register():
	"""
	Login via Twitter API
	"""
	global oauth_token, user_name
	user_name = ''
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
		user_name = data['screen_name'][0]
		user_dir  = users_dir + '/' + user_name
		if not os.path.exists(user_dir):
			os.makedirs(user_dir)
		for varname in conf_files:
			path = user_dir + '/' + varname
			f = open(path, 'w+')
			f.write(data[varname][0])
			f.close()

def tweet(string):
	url = "https://api.twitter.com/1.1/statuses/update.json"
	request = post(url, {'status': string})
	if request.status_code / 100 == 2:
		print("Successfully tweeted!")

def get_mutes():
	global mute_ids
	url = 'https://api.twitter.com/1.1/mutes/users/ids.json'
	request = get(url);
	mute_ids = json.loads(request.text)['ids']

def change_user():
	global user_name
	user_name = ''
	while not user_name in users:
		user_name = input('User name ' + str(list(users.keys())) + ' : ')

def get_config():
	"""
	Find configuration directory and get each values
	"""
	# At the beginning, look for access token.
	# If token files do not exist, register the token first.
	if not os.path.exists(users_dir) or len(os.listdir(users_dir)) == 0:
		register()
	for user_dir in [x[0] for x in os.walk(users_dir)][1:]:
		user_name = os.path.basename(user_dir)
		users[user_name] = {}
		for varname in conf_files:
			path = user_dir + '/' + varname
			if os.path.exists(path):
				f = open(path, 'r')
				read = f.read();
				users[user_name][varname] = read
				f.close()
			else:
				shutil.rmtree(user_dir)
				users.pop(user_name)
				print('Missing config file of @'+user_name+'.')
				print('Type `register()` to relogin.')
				break

get_config()
if len(users.keys()) == 0:
	# May not needed
	register()
elif len(users.keys()) == 1:
	user_name = list(users.keys())[0]
else:
	change_user()
print('Logged in as @'+user_name+'!')
