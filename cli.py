from hashlib import sha1 
import requests
import sys
import argparse
import urllib3
import json 
from termcolor import cprint
from pyfiglet import Figlet

BOOTSTRAP_IP = 'localhost'
BOOTSTRAP_PORT = '5000'
PREFIX = '/home/'


def get_greet(ip, port):
	PREFIX = '/home/'
	BASE_URL = 'http://' + str(ip) + ':' + str(port) + PREFIX
	res = requests.get(BASE_URL).json()
	return res

def check_join(ip, port):
	BASE_URL = 'http://' + BOOTSTRAP_IP + ':' + BOOTSTRAP_PORT + PREFIX + 'join/'
	bogus = {'ip' : ip , 'port' : port}
	res = requests.post(BASE_URL, params = bogus ,headers = {'content_type' : 'application/json'}).json()
	return res

def insert_key_value(ip, port, key, value):
	url = 'http://{}:{}{}insert/'.format(ip,port,PREFIX)
	params = {'key': key, 'value' : value}
	headers = {'content_type' : 'application/json'}
	res = requests.post(url, headers=headers, params=params).json()
	return res

def query_function(ip, port, key):
	url = 'http://{}:{}{}query/'.format(ip,port,PREFIX)
	params = {'key' : key}
	headers = {'content_type' : 'application/json'}
	res = requests.get(url, params=params, headers= headers).json()
	return res


def depart_node(ip, port):
	url = 'http://{}:{}{}depart/'.format(ip, port,PREFIX)
	res  = requests.post(url)
	return res.json()


def delete_key(ip, port, key):
	url = 'http://{}:{}{}delete/'.format(ip,port,PREFIX)
	headers = {'content_type' : 'application/json'}
	params = {'key' : key}
	res  = requests.post(url, headers=headers, params = params)
	return res.json()


def overlay_fn(ip,port):
	url = 'http://{}:{}{}overlay/'.format(ip, port,PREFIX)
	res  = requests.post(url).json()
	if 'nodes' in res.keys():
		nodes = res['nodes']

	return nodes


if __name__ == '__main__':

	f = Figlet(font='standard')
	#print(f.renderText('Toy Chord CLI!'))
	'''
	first, we need a parser for command line arguments
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', default = 'localhost' , help = 'ip of the device running the app')
	parser.add_argument('--port', default = '5100' ,help = 'port on which the app runs')
	parser.add_argument('--command', help = 'select action action to perform')
	parser.add_argument('--key', help = 'type key argument for insert/delete/query')
	parser.add_argument('--value', help = 'type value argument for insert ONLY')
	args = parser.parse_args()

	'''
	parse existing arguments
	'''

	ip = args.ip
	port = args.port
	command = args.command
	BASE_URL = 'http://' + str(ip) + ':' + str(port) + PREFIX
	if command == 'greet':
		print(get_greet(ip, port))
		exit(0)
	elif command == 'join':
		print(check_join(ip, port))
		exit(0)
	elif command == 'insert':
		key = args.key
		value = args.value
		print(insert_key_value(ip,port,key,value))
		exit(0)
	elif command == 'query':
		key = args.key
		print(query_function(ip, port, key))
		exit(0)
	elif command == 'depart':
		print(depart_node(ip, port))
		exit(0)
	elif command == 'overlay':
		over = overlay_fn(ip,port).replace('[','').replace(']','').split(',')
		for x in over:
			print(x)
		exit(0)
	elif command == 'delete':
		key = args.key
		print(delete_key(ip,port, key))
		exit(0)
 