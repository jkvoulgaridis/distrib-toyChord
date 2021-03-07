from flask import Flask, render_template, request, jsonify, redirect
from hashlib import sha1 
import requests
import sys
import argparse
import urllib3
import json 
from threading import Thread
import time
from itertools import islice
import os

RING_SIZE_EXP = 10   # for a given value -> 2**SIZE nodes at ring (max)
BOOTSTRAP_IP = 'localhost'
BOOTSTRAP_PORT = '5000'
PREFIX = '/home/'

class Node:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.previous_node = None
		self.next_node = None
		self.responsibility = dict()
		self.replicas = dict() 
		self.hs = hash_fn({'ip':self.ip, 'port': self.port}) 
		self.replication_factor = 1
		self.policy = None
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

def check_join(ip, port):
	BASE_URL = 'http://{}:{}{}join/'.format(BOOTSTRAP_IP,BOOTSTRAP_PORT,PREFIX)
	bogus = {'ip' : ip , 'port' : port}
	res = requests.post(BASE_URL, params = bogus ,headers = {'content_type' : 'application/json'}).json()
	return res

global flag
def join_util(ip, port):
	print('in THREAD')
	time.sleep(5)
	check_join(ip, port)
	flag = False
	exit(0)

def hash_fn(nd):
	if nd is None:
		return None
	elif isinstance(nd, dict):
		inp = '{}:{}'.format(nd['ip'] , nd['port']).encode('utf-8')
		return int(sha1(inp).hexdigest() , 16) % 2**RING_SIZE_EXP
	else:
		inp = nd.encode('utf-8')
		return int(sha1(inp).hexdigest(), 16) % 2**RING_SIZE_EXP

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

@app.route(PREFIX  , methods = ['GET'])
def home_greet():
	print(type(node.format_next()))
	print(node.format_prev())
	return jsonify({'current' : '{}:{}'.format(node.ip, node.port),\
		'nodehash' : node.nodehash() , 'prev' : node.format_prev(), 'next' : node.format_next(), \
		'resps': node.responsibility, 'replicas': node.replicas, 'replication' : node.replication_factor})

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
			print('new node hash val: {}'.format(nhs))	
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
		url = "http://{}:{}{}join/".format(ip,port,PREFIX)
		res = requests.post(url,\
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
		new_dict= dict()
		for k in node.responsibility.keys():
			if k <= hash_fn(node.previous_node) or \
			(k > node.nodehash() and k > hash_fn(node.previous_node)):
				new_dict[k] = node.responsibility[k]
		for i in new_dict.keys():
			print ('{} -> {}'.format(i, new_dict[i]))
			del node.responsibility[i]
		params = {'dict' : json.dumps(new_dict)}
		headers = {'content_type' : 'application/json'}
		url ='http://{}:{}{}insert/'.format(node.previous_node["ip"],\
			node.previous_node["port"], PREFIX)
		res = requests.post(url , params=params, headers=headers)

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

	elif (nhs > node.nodehash() and nhs < hash_fn(node.next_node) and node.nodehash() < hash_fn(node.next_node)) \
		 or ((node.nodehash() > hash_fn(node.next_node)) and  (nhs > node.nodehash()  or nhs < hash_fn(node.next_node))):

		'''
		the following if-else statement determines if a node should be placed
		between the current node and its next, or be forwarded to next node to process
		'''

		params = {'status' : 200, 'command' : 'update-previous', 'ip' : ip, 'port' : port}
		headers = {'content_type'  :  'application/json'}
		url ='http://{}:{}{}join/'.format(node.next_node["ip"],node.next_node["port"], PREFIX)
		print('IN FORWARD IF')
		print(url)
		res = requests.post(url,headers=headers, params= params)
		print(res.json())

		#step 2 : inform new node about his new neighbors
		params2 = {'status':200, 'command':'update-both', 'prev_ip': node.ip, 'prev_port' : node.port, \
		'nxt_ip' : node.next_node['ip'] , 'nxt_port' : node.next_node['port']}
		headers = {'content_type'  :  'application/json'}
		url_2 = 'http://{}:{}{}join/'.format(ip, port, PREFIX)
		res2 = requests.post(url_2, headers=headers, params= params2)
		print('in 2 strp command')	

		#step 3 
		node.next_node = {'ip' : ip, 'port' : port}
		return jsonify({'status':200, 'resp': 'in a cmd with 2 steps'})
	else:

		print('forward to next node')
		params = {'status' : 200, 'ip' : ip, 'port' : port}
		headers = {'content_type': 'application/json'}
		url ='http://{}:{}{}join/'.format(node.next_node['ip'],node.next_node['port'], PREFIX)
		res = requests.post(url,headers=headers, params = params)
		return jsonify({'status':200, 'resp': 'forward'})

'''

DEPART of nodes in dht. 

'''

@app.route(PREFIX + 'depart/', methods = ['GET' , 'POST'])
def depart_node():	
	dic = node.responsibility
	url_ = 'http://{}:{}{}insert/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
	headers = {'content_type' : 'application/json'}
	for k in dic.keys():
		params = {'key' : k, 'value' : dic[k]}
		requests.post(url_, headers=headers, params= params)

	if node.next_node['ip'] == node.previous_node['ip'] and node.next_node['port'] == node.previous_node['port']:
		params = { 'command' : 'set-none' }
		url = 'http://{}:{}{}join/'.format(node.previous_node["ip"],node.previous_node["port"],PREFIX)
		res = requests.post(url, headers=headers, params=params).json()
	else:	
		params = {'ip' : node.next_node["ip"] , 'port' : node.next_node["port"] , 'command' : 'update-next'}
		url = 'http://{}:{}{}join/'.format(node.previous_node["ip"],node.previous_node["port"],PREFIX)
		res = requests.post(url, headers=headers, params=params).json()
		print(res['status'])

		if 'status' in res.keys():
			if res['status'] != 200:
				return jsonify({'status' : 400, 'resp' : 'node departure failed'})

		params = {'ip' : node.previous_node["ip"] , 'port' : node.previous_node["port"] , 'command' : 'update-previous'}
		url = 'http://{}:{}{}join/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
		res = requests.post(url, headers=headers, params=params).json()

		if 'status' in res.keys():
			if res['status'] != 200:
				return jsonify({'status' : 400, 'resp' : 'node departure failed'})
	return jsonify({'status' : 200, 'resp': 'node departed gracefully'})



'''
INSERT METHOD ADDS NEW DATA TO DHT
'''

@app.route(PREFIX + 'insert/', methods = ['GET', 'POST'])
def insert_file():
	if request.content_type == 'application/json':

		if 'key' in request.args and 'value' in request.args:
			key = request.args['key']
			value = request.args['value']
			key_hash = hash_fn(key)

			if 'rf' in request.args:
				rf = int(request.args['rf'])
				if key_hash not in node.responsibility.keys():
					node.replicas[key_hash] = value
					rf -= 1
					if rf > 0:
						print('inserting replica')
						url='http://{}:{}{}insert/'.format(node.next_node['ip'],node.next_node['port'],PREFIX)
						headers={'content_type' : 'application/json'}
						params = {'rf' : rf, 'key' : key, 'value' : value}
						res= requests.post(url, headers=headers, params=params)
						return jsonify({'status' : 200 , 'resp' : 'replica added'})
					else:
						print('added last replica')
						return jsonify({'status': 200, 'resp' : 'inserted values and replicas'})

			if ((key_hash <= node.nodehash() and key_hash > hash_fn(node.previous_node) and node.nodehash() > hash_fn(node.previous_node)) or\
				(node.nodehash() < hash_fn(node.previous_node) and (key_hash > hash_fn(node.previous_node) or key_hash < node.nodehash()))):
				#add key to respinsibility dictionary
				node.add_responsibility(key_hash, value)
				#inform next nodes about replication
				url='http://{}:{}{}insert/'.format(node.next_node['ip'],node.next_node['port'],PREFIX)
				headers={'content_type' : 'application/json'}
				params = {'rf' : node.replication_factor, 'key' : key, 'value' : value}
				res= requests.post(url, headers=headers, params=params)
				return jsonify({'status' : 200, 'resp' : 'added <key,value> pair'})
			else:

				headers = {'content_type' : 'application/json'}
				params = {'key' : key, 'value' : value}
				url ='http://{}:{}{}insert/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
				res = requests.post(url, headers=headers, params=params)
				return jsonify({'status' : 200, 'resp' : 'forwarded <key,value> pair'})

		elif 'dict' in request.args:
			dict_ = json.loads(request.args['dict'])
			print(dict_)
			node.responsibility.update(dict_)
			return jsonify({'status' : 200, 'resp' : 'dictionary insertion OK'})
		else:
			return jsonify({'status' : 400, 'resp' : 'bad request (check content_type header)'})


@app.route(PREFIX + 'delete/', methods=['POST', 'GET'])
def delete_fn():
	if request.content_type == 'application/json':
		if 'key' in request.args:
			key = request.args['key']
			key_hash = hash_fn(key)

		else:
			return jsonify({'status' : 400, 'resp' : 'bad request - no key argument'})

		if 'rf' in request.args:
			rf = int(request.args['rf'])
			if key_hash in node.replicas:
				del node.replicas[key_hash]
			if key_hash in node.responsibility:
				del node.responsibility[key_hash]
			rf -= 1
			if rf > 0:
				headers = {'content_type' : 'application/json'}
				params = {'key'  : key, 'rf' : node.replication_factor}
				url = 'http://{}:{}{}delete/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
				res = requests.post(url,headers=headers, params=params)
			else:
				return jsonify({'status': 200, 'resp' : 'key and all replicas removed'})

			return jsonify({'status' : 200, 'resp' : 'removed a replica'})

		if ((key_hash <= node.nodehash() and key_hash > hash_fn(node.previous_node) and node.nodehash() > hash_fn(node.previous_node)) or\
		(node.nodehash() < hash_fn(node.previous_node) and (key_hash > hash_fn(node.previous_node) or key_hash < node.nodehash()))):
			if key_hash in node.responsibility.keys():
				del node.responsibility[key_hash]
				if node.replication_factor > 0:
					headers = {'content_type' : 'application/json'}
					params = {'key'  : key, 'rf' : node.replication_factor}
					url = 'http://{}:{}{}delete/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)	
					res = requests.post(url, headers=headers, params=params)

				return jsonify({'status' : 200 , 'resp' : 'key removed'})
			else:
				return jsonify( {'status' : 200 , 'resp' : 'key not in dht'})
		else:
			headers = {'content_type' : 'application/json'}
			params = {'key'  : key}
			url = 'http://{}:{}{}delete/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
			res =  requests.post(url , params=params, headers=headers)
			return res.json()
	else:
		return jsonify({'status' : 400, 'resp' : 'bad request  - check content type'})


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

	if node.policy == 'EL':
		if key_hash in node.replicas.keys():
			value = node.replicas[key_hash]
			return jsonify({'status' : 200, 'resp' : 'found key', 'key' : key, 'value' : value})


	if 'rf' in request.args:
		rf = int(request.args)
		if rf == 1:
			if key_hash in node.replicas.keys():
				value = node.replicas[key_hash]
				return jsonify({'status' : 200, 'resp' : 'found key', 'key' : key, 'value' : value})
		else:
			rf -= 1
			headers = {'content_type' : 'application/json'}
			params = {'key'  : key, 'rf' : rf}
			url = 'http://{}:{}{}query/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)	
			res = requests.post(url, headers=headers, params=params)
			return re.json()


	if ((key_hash <= node.nodehash() and key_hash > hash_fn(node.previous_node) and node.nodehash() > hash_fn(node.previous_node)) or\
		(node.nodehash() < hash_fn(node.previous_node) and (key_hash > hash_fn(node.previous_node) or key_hash < node.nodehash()))):
		if key_hash in node.responsibility.keys():
			if node.policy == 'EC':		# when we want eventual consistency we get the first copy found
				value = node.responsibility[key_hash]
				return jsonify({'status' : 200, 'resp' : 'found key', 'key' : key, 'value': value})
			else:
				#In this case we will return the last replica
				headers = {'content_type' : 'application/json'}
				params = {'key'  : key, 'rf' : node.replication_factor}
				url = 'http://{}:{}{}query/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)	
				res = requests.post(url, headers=headers, params=params)
				return re.json()
		else:
			return jsonify({'status' : 404, 'resp' : 'key not in DHT'})
	else:
		print('FORWARDED QUERY')
		params = {'key' : key}
		headers = {'content_type' : 'application/json'}
		url = 'http://{}:{}{}query/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
		res = requests.post(url, params=params, headers= headers)
		return res.json()


@app.route(PREFIX + 'overlay/' , methods=['GET', 'POST'])
def overlay_fn():
	if 'nodes' not in request.args:
		nodes = list()
		nodes.append('{}:{}'.format(node.ip, node.port))
	else:
		nodes = json.loads(request.args['nodes'])
		if '{}:{}'.format(node.ip,node.port) in nodes:
			return jsonify({'status': 200, 'nodes' : json.dumps(nodes)}) 
		else:
			print('NODES : {}'.format(nodes))
			print(type(nodes))
			nodes.append('{}:{}'.format(node.ip,node.port))
	print('NODES : {}'.format(nodes))
	url = 'http://{}:{}{}overlay/'.format(node.next_node["ip"],node.next_node["port"],PREFIX)
	params = {'nodes' : json.dumps(nodes)}
	headers = {'content_type'  : 'application/json'}
	res= requests.post(url, headers=headers, params=params)
	print(res)
	return res.json()


'''
main routine running when .py file runs

'''

def run_util(ip,port):
	app.run(port=port, host = ip, debug= True)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--ip', default = 'localhost' , help = 'ip of the device running the app')
	parser.add_argument('--port', default = '5100',help = 'port on which the app runs')
	parser.add_argument('--bootstrap' ,default = False, action = 'store_true', help = 'used to launch first node')
	parser.add_argument('--policy', default='EC' ,help = 'policy = [linearizability (L) | eventual_consistency] (EC)')
	parser.add_argument('--replication', default=1, help = 'pick replication factor')
	args = parser.parse_args()

	bootstrap = args.bootstrap
	if args.ip is not None and args.bootstrap is False:
		print('ip : {}'.format(args.ip))
		ip = args.ip

	if args.port is not None and args.bootstrap is False:
		print('port : {}'.format(args.port))
		port = args.port

	if args.bootstrap is True:
		print('bootstrap node launced')
		ip = BOOTSTRAP_IP
		port = BOOTSTRAP_PORT
		print('node ip : {}'.format(ip))
		print('binded port : {}'.format(port))

	
	
	node = Node(ip, port)
	node.replication_factor = int(args.replication)
	node.policy = args.policy

	print(node.nodehash())

	if bootstrap is True:
		app.run(host=ip, port=port, debug=False)
	
	n = os.fork()
	if n == 0:
		time.sleep(2)
		res= check_join(ip, port)
		print(res)
		exit(0)
	elif n > 0:
		app.run(host=ip, port=port, debug=False)		
	else:
		print('Error in booting node :(')	
	