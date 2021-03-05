from hashlib import sha1 
import requests
import sys
import argparse
import urllib3
import json 
from termcolor import cprint
from pyfiglet import Figlet


PREFIX = '/home/'

def get_greet(ip, port):
	PREFIX = '/home/'
	BASE_URL = 'http://' + str(ip) + ':' + str(port) + PREFIX
	res = requests.get(BASE_URL).json()
	return res

def check_join(ip, port):
	BASE_URL = 'http://' + 'localhost' + ':' + '5000' + PREFIX + 'join/'
	bogus = {'ip' : ip , 'port' : port}
	res = requests.post(BASE_URL, params = bogus ,headers = {'content_type' : 'application/json'}).json()
	return res

def insert_key_value(ip, port, key, value):
	url = f'http://{ip}:{port}/{PREFIX}insert/'
	params = {'key': key, 'value' : value}
	headers = {'content_type' : 'application/json'}
	res = requests.post(url, headers=headers, params=params).json()
	return res

def query_function(ip, port, key):
	url = f'http://{ip}:{port}{PREFIX}query/'
	params = {'key' : key}
	headers = {'content_type' : 'application/json'}
	res = requests.get(url, params=params, headers= headers).json()
	return res


def depart_node(ip, port):
	url = f'http://{ip}:{port}{PREFIX}depart/'
	res  = requests.post(url)
	return res.json()


def delete_key(ip, port, key):
	url = f'http://{ip}:{port}{PREFIX}delete/'
	headers = {'content_type' : 'application/json'}
	params = {'key' : key}
	res  = requests.post(url, headers=headers, params = params)
	return res.json()


def overlay_fn(ip,port):
	url = f'http://{ip}:{port}{PREFIX}overlay/'
	res  = requests.post(url).json()
	if 'nodes' in res.keys():
		nodes = res['nodes']

	return nodes


if __name__ == '__main__':

	f = Figlet(font='standard')
	print(f.renderText('Toy Chord CLI!'))
	'''
	first, we need a parser for command line arguments
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', default = 'localhost' , help = 'ip of the device running the app')
	parser.add_argument('--port', default = '5000' ,help = 'port on which the app runs')
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
 