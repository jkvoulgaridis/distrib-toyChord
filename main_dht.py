from flask import Flask, render_template, request, jsonify, redirect
from hashlib import sha1 
import requests
import sys
import argparse
import urllib3
import json 
import _thread 
import time
from itertools import islice


BOOTSTRAP_IP = 'localhost'
BOOTSTRAP_PORT = '5000'
PREFIX = '/home/'

def check_join(ip, port):
	BASE_URL = f'http://{BOOTSTRAP_IP}:{BOOTSTRAP_PORT}{PREFIX}join/'
	bogus = {'ip' : ip , 'port' : port}
	res = requests.post(BASE_URL, params = bogus ,headers = {'content_type' : 'application/json'}).json()
	return res

def join_util(ip, port):
	print('in THREAD')
	time.sleep(5)
	check_join(ip, port)

def hash_fn(nd):
	if nd is None:
		return None
	elif isinstance(nd, dict):
		inp = f'{nd["ip"]}:{nd["port"]}'.encode('utf-8')
		return int(sha1(inp).hexdigest() , 16) % 2**160
	else:
		inp = nd.encode('utf-8')
		return int(sha1(inp).hexdigest(), 16) % 2**160

class Node:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.previous_node = None
		self.next_node = None
		self.responsibility = dict()
		self.hs = hash_fn({'ip':self.ip, 'port': self.port}) 
	def nodehash(self):
		return self.hs
	def add_responsibility(self, key, value):
		self.responsibility[key] = value
	def format_prev(self):
		if self.previous_node is None:
			return None
		return str(self.previous_node['ip']+ ':' + self.previous_node['port'])
	def format_next(self):
		if self.next_node is None:
			return None
		return str(self.next_node['ip'] + ':' + self.next_node['port'])

app = Flask(__name__)

global node


'''

/ ENDPOINT redirects redirects to /home/ 

'''



@app.route('/')
def home():
	print('in home')
	return redirect(PREFIX)







'''
GET BASIC info from current node 
'''










@app.route( PREFIX  , methods = ['GET'])
def home_greet():
	print(type(node.format_next()))
	print(node.format_prev())
	return jsonify({'current' : f'{node.ip}:{node.port}',\
		'nodehash' : node.nodehash() , 'prev' : node.format_prev(), 'next' : node.format_next(), \
		'resps': node.responsibility})








'''
ADD new nodes to DHT
'''






@app.route(PREFIX + 'join/', methods = ['POST', 'GET'])
def join_node():
	'''
	CHECK if ip, port of the new node who wants to join are present 
	'''

	if request.content_type == 'application/json':
		if 'ip' in request.args and 'port' in request.args:
			ip = request.args['ip']
			port = request.args['port']
			nhs = hash_fn({'ip':ip, 'port':port})
			print(f'new node hash val: {nhs}')	
		if 'command' in request.args:
			cmd = request.args['command']
		else:
			cmd = None			
	else:
		return jsonify({'status' : 400, 'resp' : 'error in format'})

	'''
	next if clause  is True for when the first node after bootstrap enters
	'''

	if bootstrap is True and node.previous_node == None and node.next_node == None:
		print('adding first Node...')
		node.previous_node = {'ip' : ip , 'port' : port}
		node.next_node = {'ip' : ip , 'port' : port}
		params = {'status' : 200 , 'command' : 'from-bootstrap-register-both',\
			'ip': node.ip, 'port' : node.port} 
		res = requests.post(f'http://{ip}:{port}{PREFIX}join/',\
			params = params, headers = {'content_type' : 'application/json'})
		print(res.json())
		return jsonify({'status': 200, 'resp' : 'added first node (bootstrap out)'})

	elif cmd == 'from-bootstrap-register-both':
		'''
		with bootstrap-register-both command the first node (after bootstrap is added)
		'''
		print('from bootstrap update')
		node.previous_node = {'ip' : ip , 'port' : port}
		node.next_node = {'ip' : ip , 'port' : port}
		return jsonify({'status' : 200, 'resp' : 'updated both'})


	elif cmd == 'update-previous':
		'''
		when a new node should be placed between two adjecents nodes, 
		the first nodes informs the later about his new neighbor (new node)
		'''		
		print('In update previous command')
		node.previous_node = {'ip' : ip , 'port' : port}
		return jsonify({'status' : 200})

	elif cmd == 'update-next':
		print('In update next command')
		node.next_node = {'ip' : ip , 'port' : port}
		return jsonify({'status' : 200})

	elif cmd == 'update-both':
		'''
		the update both command updates both previous and next nodes of a node
		'''
		print('update-both command')
		node.previous_node = {'ip' : request.args['prev_ip'] , 'port' : request.args['prev_port']}
		node.next_node = {'ip' : request.args['nxt_ip'], 'port' : request.args['nxt_port']}
		return jsonify({'status':200, 'resp': 'update done'})

	elif cmd == 'set-none':
		node.previous_node = None
		node.next_node = None
		return jsonify({'status' : 200 , 'resp' : 'join/update done'})

	elif (nhs > node.nodehash() and nhs < hash_fn(node.next_node) and node.nodehash() < hash_fn(node.next_node)) or \
	   (node.nodehash() > hash_fn(node.next_node)):

		'''
		the following if-else statement determines if a node should be placed
		between the current node and its next, or be forwarded to next node to process
		'''
		params = {'status' : 200, 'command' : 'update-previous', 'ip' : ip, 'port' : port}
		headers = {'content_type'  :  'application/json'}
		url = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}join/'
		print('IN FORWARD IF')
		print(url)
		res = requests.post(url,headers=headers, params= params)
		print(res.json())
		#step 2 : inform new node about his new neighbors
		params2 = {'status':200, 'command':'update-both', 'prev_ip': node.ip, 'prev_port' : node.port, \
		'nxt_ip' : node.next_node['ip'] , 'nxt_port' : node.next_node['port']}
		headers = {'content_type'  :  'application/json'}
		res2 = requests.post(f'http://{ip}:{port}{PREFIX}join/',\
			headers=headers, params= params2)
		print('in 2 strp command')	
		node.next_node = {'ip' : ip, 'port' : port}
		return jsonify({'status':200, 'resp': 'in a cmd with 2 steps'})


	else:

		print('forward to next node')
		params = {'status' : 200, 'ip' : ip, 'port' : port}
		headers = {'content_type': 'application/json'}
		res = requests.post(f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}join/',\
			headers=headers, params = params)
		return jsonify({'status':200, 'resp': 'forward'})








'''
INSERT METHOD ADDS NEW DATA TO DHT
'''






@app.route(PREFIX + 'insert/', methods = ['GET', 'POST'])
def insert_file():
	if request.content_type == 'application/json':
		if 'key' in request.args and 'value' in request.args:
			key = request.args['key']
			value = request.args['value']
		else:
			return jsonify({'status': 300, 'resp' : 'invalid arguments passed'})
	else:
		return jsonify({'status' : 350, 'resp' : 'invalid data format'})
	key_hash = hash_fn(key)
	if ((key_hash <= node.nodehash() and key_hash > hash_fn(node.previous_node) and node.nodehash() > hash_fn(node.previous_node)) or\
		(node.nodehash() < hash_fn(node.previous_node) and (key_hash > hash_fn(node.previous_node) or key_hash < node.nodehash()))):
		node.add_responsibility(key_hash, value)
		return jsonify({'status' : 200, 'resp' : 'added <key,value> pair'})
	else:
		headers = {'content_type' : 'application/json'}
		params = {'key' : key, 'value' : value}
		url = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}insert/'
		res = requests.post(url, headers=headers, params=params)
		return jsonify({'status' : 200, 'resp' : 'forwarded <key,value> pair'})





'''

QUERY endpoint searches keys in dht

'''





@app.route(PREFIX + 'query/', methods = ['GET', 'POST'])
def query_fn():
	if request.content_type == 'application/json':
		key = request.args['key']
	else:
		return jsonify({'status' : 400, 'resp' : 'bad format'})
	key_hash = hash_fn(key)
	if bootstrap is True:
		print('IN BOOTSTRAP QUERY')
		if 'status' in request.args:
			if request.args['status'] == '200':
				return jsonify({'value' : request.args['value']})
			else:
				return jsonify({'value' : 'key not in dht'})

	if ((key_hash <= node.nodehash() and key_hash > hash_fn(node.previous_node) and node.nodehash() > hash_fn(node.previous_node)) or\
		(node.nodehash() < hash_fn(node.previous_node) and (key_hash > hash_fn(node.previous_node) or key_hash < node.nodehash()))):
		if key_hash in node.responsibility.keys():
			value = node.responsibility[key_hash]
			params = {'status' : 200 , 'key' :key, 'value' : value}
			headers = {'content_type' : 'application/json'}
			url = f'http://{BOOTSTRAP_IP}:{BOOTSTRAP_PORT}{PREFIX}query/'
			res = requests.post(url, params=params, headers= headers)
			print('FOUND KEY')
			return res.json()
		else:
			url = f'http://{BOOTSTRAP_IP}:{BOOTSTRAP_PORT}{PREFIX}query/'
			params = {'status' : 404, 'key' : key}
			headers = {'content_type' : 'application/json'}
			print('KEY NOT IN DHT')
			res = requests.post(url, params=params, headers= headers)		
			return res.json()
	else:
		print('FORWARDED QUERY')
		params = {'key' : key}
		headers = {'content_type' : 'application/json'}
		url = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}query/'
		res = requests.post(url, params=params, headers= headers)
		return res.json()







'''

DEPART of nodes in dht. 

'''




@app.route(PREFIX + 'depart/', methods = ['GET' , 'POST'])
def depart_node():	
	dic = node.responsibility
	url_ = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}insert/'
	headers = {'content_type' : 'application/json'}
	for k,v in enumerate(dic):
		params = {'key' : k, 'value' : v}
		requests.post(url_, headers=headers, params= params)

	if node.next_node['ip'] == node.previous_node['ip'] and node.next_node['port'] == node.previous_node['port']:
		params = { 'command' : 'set-none' }
		url = f'http://{node.previous_node["ip"]}:{node.previous_node["port"]}{PREFIX}join/'
		res = requests.post(url, headers=headers, params=params).json()
	else:	
		params = {'ip' : node.next_node["ip"] , 'port' : node.next_node["port"] , 'command' : 'update-next'}
		url = f'http://{node.previous_node["ip"]}:{node.previous_node["port"]}{PREFIX}join/'
		res = requests.post(url, headers=headers, params=params).json()
		print(res['status'])

		if 'status' in res.keys():
			if res['status'] != 200:
				return jsonify({'status' : 400, 'resp' : 'node departure failed'})

		params = {'ip' : node.previous_node["ip"] , 'port' : node.previous_node["port"] , 'command' : 'update-previous'}
		url = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}join/'
		res = requests.post(url, headers=headers, params=params).json()

		if 'status' in res.keys():
			if res['status'] != 200:
				return jsonify({'status' : 400, 'resp' : 'node departure failed'})

	return jsonify({'status' : 200, 'resp': 'node departed gracefully'})



@app.route(PREFIX + 'overlay/' , methods=['GET', 'POST'])
def overlay_fn():
	if 'nodes' not in request.args:
		nodes = list()
		nodes.append(f'{node.ip}:{node.port}')
	else:
		nodes = json.loads(request.args['nodes'])
		if f'{node.ip}:{node.port}' in nodes:
			return jsonify({'status':200, 'nodes' : json.dumps(nodes)}) 
		else:
			print(f'NODES : {nodes}')
			print(type(nodes))
			nodes.append(f'{node.ip}:{node.port}')
	print(f'NODES : {nodes}')
	url = f'http://{node.next_node["ip"]}:{node.next_node["port"]}{PREFIX}overlay/'
	params = {'nodes' : json.dumps(nodes)}
	headers = {'content_type'  : 'application/json'}
	res= requests.post(url, headers=headers, params=params)
	print(res)
	return res.json()






'''

main routine running when .py file runs

'''



if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', default = 'localhost' , help = 'ip of the device running the app')
	parser.add_argument('--port', default = '5100',help = 'port on which the app runs')
	parser.add_argument('--bootstrap' ,default = False, action = 'store_true', help = 'used to launch first node')

	args = parser.parse_args()	
	bootstrap = args.bootstrap
	if args.ip is not None and args.bootstrap is False:
		print(f'ip : {args.ip}')
		ip = args.ip

	if args.port is not None and args.bootstrap is False:
		print(f'port : {args.port}')
		port = args.port

	if args.bootstrap is True:
		print('bootstrap node launced')
		ip = BOOTSTRAP_IP
		port = BOOTSTRAP_PORT
		print(f'node ip : {ip}')
		print(f'binded port : {port}')

	node = Node(ip, port)
	print(node.nodehash())
	#if bootstrap is False:
	#	_thread.start_new_thread(join_util, (ip,port,))

	app.run(port=port, host = ip, debug= True)
	