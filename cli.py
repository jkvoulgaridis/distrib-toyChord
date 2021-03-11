from hashlib import sha1 
import requests
import sys
import argparse
import urllib3
import json 
from termcolor import cprint
from pyfiglet import Figlet
import time
from random import randint
import asyncio
import aiohttp


TEST = False

done = lambda x : cprint(x , 'green')
fail = lambda x : cprint(x , 'red') 
warn = lambda x : cprint(x , 'yellow')
ips = ['192.168.0.1' , '192.168.0.2' , '192.168.0.3' , '192.168.0.4' ,'192.168.0.5' ]
ports = [5000, 6000]

if TEST is False:
	BOOTSTRAP_IP = '192.168.0.1'
	BOOTSTRAP_PORT = '5000'	
	RING_SIZE_EXP = 100   # for a given value -> 2**SIZE nodes at ring (max)
else:
	BOOTSTRAP_IP = 'localhost'
	BOOTSTRAP_PORT = '5000'
	RING_SIZE_EXP = 10   # for a given value -> 2**SIZE nodes at ring (max)


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
	res = requests.post(url, params=params, headers= headers).json()
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
	parser.add_argument('--ip', default = None ,\
		help = 'ip of the device we address the command. --ip '+\
		'and --port can be used in any command [ insert,delete, query, depart, overlay, greet ]')
	parser.add_argument('--port', default = None ,\
		help = 'port on which we address the command! '+\
		'--ip and --port can be used in any command [ insert,delete, query, depart, overlay, greet ]')
	parser.add_argument('--greet'  , action = 'store_true',\
		help ='print info about a node. Requires --ip and --port args')
	parser.add_argument('--depart'  , action = 'store_true',\
		help ='kick a node out of the DHT. Requires --ip and --port args')
	parser.add_argument('--insert'  , action = 'store_true',\
		help ='Add <key,value> pair to DHT. ' +\
		'Requires --key <key> and --value <value> args or just --filename <file>')
	parser.add_argument('--delete'  , action = 'store_true', help ='')
	parser.add_argument('--overlay'  , action = 'store_true',\
		help ='print network topology '+\
		'startinf from a node. Required args: --ip and --port')
	parser.add_argument('--query'  , action = 'store_true',\
		help ='search a given key in the DHT. Required args --key <key> or --filename <file>')
	parser.add_argument('--experiment'  , action = 'store_true',\
		help ='This command requires --filename <file>. This command is used for multi-type commands '+\
		'form a file, e.g. a file with inserts and queries')	
	parser.add_argument('--key', help = 'type the KEY argument for insert/delete/query.')
	parser.add_argument('--value', help = 'type value argument for insert ONLY! used only for insert.')
	parser.add_argument('--filename', default=None,\
		help = 'if command == insert OR query read keys,values'+\
		'from a given file.' +\
		' When this argument is '+\
		' used no other key or value args should be provided!')
	args = parser.parse_args()

	'''
	parse existing arguments
	'''
	
	if args.greet is True:
		command = 'greet'
	elif args.depart is True:
		command = 'depart'
	elif args.insert is True:
		command = 'insert'
	elif args.delete is True:
		command = 'delete'
	elif args.query is True:
		command = 'query'
	elif args.overlay is True:
		command = 'overlay'
	elif args.experiment is True:
		command = 'experiment'
	else:
		err_msg = 'ERROR: no command was given as input.\nType --help for more'
		fail(err_msg)
		exit(1)


	if args.key is None and args.value is None and args.filename is None:
		if command in ['delete', 'query', 'experiment']:
			msg = 'ERROR: command [ {} ] requires --key or --filename'.format(command)
			fail(msg)
			exit(1)
		elif command == 'insert':
			msg = 'ERROR: command [ {} ] requires (--key and --value) or --filename'.format(command)
			fail(msg)
			exit(1)
		else:
			pass


	if args.ip is None or args.port is None:
			if command in ['depart' , 'overlay', 'greet']:
				msg = 'command [ {} ] requires --ip and --port args'.format(command)
				fail(msg)
				exit(1)
	else:
		pass


	if args.ip is None:
		ip = ips[randint(0,7)%5]
		warn('No --ip provided, choosing an ip at random')
	else:
		ip = args.ip


	if args.port is None:
		port = ports[randint(0,3)%2]
		warn('No --port is provided, choosing 5000 or 6000 at random')
	else:
		port = args.port


	BASE_URL = 'http://' + str(ip) + ':' + str(port) + PREFIX

	if command == 'greet':
		print(get_greet(ip, port))
		exit(0)
	elif command == 'join':
		print(check_join(ip, port))
		exit(0)
	elif command == 'insert':
		if args.filename is not None:
			with open(args.filename, 'r') as f:
				start = time.time()
				for line in f:
					line = line.split(',')
					if len(line) == 2:
						key = line[0].strip()
						value = line[1].strip('\n')
						rand_ip = ips[randint(0,5) % 5]
						rand_port = ports[randint(0,2) % 2]
						res = insert_key_value(rand_ip,rand_port,key,value)
						print(res)
				end = time.time()
				dur = end-start
				print('Elapsed time: {} min : {:.2f} secs'.format(dur // 60, dur%60))
			exit(0)
		else:
			key = args.key
			value = args.value
			print(insert_key_value(ip,port,key,value))
			exit(0)

	elif command == 'query':
		if args.filename is not None:
			start = time.time()
			with open(args.filename , 'r') as f:
				for line in f:
					key = line.strip('\n')
					rand_ip = ips[randint(0,5) % 5]
					rand_port = ports[randint(0,2) % 2]
					res = query_function(rand_ip,rand_port,key)
					#print(res)
					if res['status'] == 200 or res['status'] == '200':
						done(res['resp'])
				end = time.time()
				dur = end-start
				print('Elapsed time: {} min : {:.2f} secs'.format(dur // 60, dur%60))
			exit(0)
		else:
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

	elif command == 'experiment':
		with open(args.filename, 'r') as f:
			start = time.time()
			for line in f:
				rand_ip = ips[randint(0,5) % 5]
				rand_port = ports[randint(0,2) % 2]
				line = line.split(',')
				if line[0].strip() == 'insert':
					res = insert_key_value(ip, port, line[1].strip(), line[2].strip('\n'))
					print('inserted {} key with value {}'.format(key, value))
					print(res)
				elif line[0].strip() == 'query':
					key = line[1].strip().strip('\n')
					res = query_function(ip, port, key)
					print('found result for key : {} is value: {}'.format(res['key'],res['value']))
					print(res)
				else:
					print('error, exiting...')
					exit(1)
		end = time.time()
		dur = end-start
		print('Elapsed time: {} min : {:.2f} secs'.format(dur // 60, dur%60))
		print('DONE, exiting experiment...')
		exit(0)
 
