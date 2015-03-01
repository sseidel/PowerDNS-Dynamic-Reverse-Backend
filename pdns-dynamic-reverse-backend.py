#!/usr/bin/python
#
"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2015 Sebastian "sseidel" Seidel


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import sys, os
import re
import syslog
import time
import math
from threading import Thread
import netaddr
import xml.etree.ElementTree as ET
from thread import start_new_thread, allocate_lock
#syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
#syslog.openlog(os.path.basename('/etc/powerdns/log'), syslog.LOG_PID)
syslog.openlog('/etc/powerdns/log',0, syslog.LOG_LOCAL4)
syslog.syslog('starting up')

DNS    = 'mandelbrot.zaphods.net'  # this nameserver
EMAIL  = 'zaphodb.zaphods.net'  # this nameserver administrator
TTL    = 300                    # time to live
RANGES = []
NEWRANGES = []
liste = []
#DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'
DIGITS = '0123456789abcdef'
lock = allocate_lock()
error=0

def mycopy(src,dst):
	for range, key in enumerate(src):
		ip = key
		ip.forward = key.forward
		ip.domain = key.domain
		ip.dns = key.dns
		ip.email = key.email
		ip.ttl = key.ttl
		ip.nameserver = key.nameserver
		ip.domain = key.domain
		dst.append(ip)

def createAndAddIPv4(prefix,prefix_len,forward,dns,mail,ttl,nameserver):
	global error
	parts = prefix.split('.')
	subnetze=0
	subnetted=-1
	#print error
	if int(prefix_len) < 32 and int(prefix_len) > 24:
		subnetze = pow(2 , 32 - int(prefix_len) )
		subnetted = 4
	elif int(prefix_len) <= 24 and int(prefix_len) > 16:
		subnetze = pow(2 , 24 - int(prefix_len) )
		subnetted = 3
	elif int(prefix_len) <= 16 and int(prefix_len) > 8:
		subnetze = pow(2 , 16 - int(prefix_len) )
		subnetted = 2
	elif int(prefix_len) <= 8 and int(prefix_len) > 0:
		subnetze = pow(2 , 8 - int(prefix_len) )
		subnetted = 1
	else:
		subnetze =100
	
	for i in range(0 , subnetze):
		try:
			ip=netaddr.IPNetwork(prefix+"/"+prefix_len)
			ip.forward = forward
			#ip.domain = domain
			ip.dns = dns
			ip.email = mail
			ip.ttl = ttl
			ip.nameserver = nameserver
			if subnetted == 1:
				ip.domain=str(i+int(parts[0]))+'.in-addr.arpa'
			elif subnetted == 2:
				ip.domain=str(i+int(parts[1]))+'.'+str(parts[0])+'.in-addr.arpa'
			elif subnetted == 3:
				ip.domain=str(i+int(parts[2]))+'.'+str(parts[1])+'.'+str(parts[0])+'.in-addr.arpa'
			elif subnetted == 4:
				ip.domain=str(i+int(parts[3]))+'.'+str(parts[2])+'.'+str(parts[1])+'.'+str(parts[0])+'.in-addr.arpa'
			else:
				ip.domain = 'error'
				#print >>sys.stdout,'error'
	 		NEWRANGES.append(ip)
		except:
			error=1
			# TODO
			syslog.syslog('error')

def createAndAddIPv6(prefix,prefix_len,forward,dns,mail,ttl,nameserver):
	global error
	try:
		ip=netaddr.IPNetwork(prefix+"/"+prefix_len)
		ip.forward = forward
		ip.domain = 'ip6.arpa'
		ip.dns = dns
		ip.email = mail
		ip.ttl = ttl
		ip.nameserver = nameserver
		prefix_len_base4=int(prefix_len)/4
		hextext = hex(ip.ip)[2:34]
		for i in range(0,int(prefix_len_base4)):
			ip.domain = str(hextext[i:i+1])+'.'+ip.domain
		NEWRANGES.append(ip)
	except:
		error=1
		# TODO
		syslog.syslog('error')

class NSrecord(object):
	def __init__(self,domain):
		self.domain=domain
	def setTTL(self,ttl):
		self.ttl=ttl
	def setMail(self,email):
		self.email=email
	def setForward(self,forward):
		self.forward=forward
	def setDns(self,dns):
		self.dns=dns
	def setNameserver(self,nameserver):
		self.nameserver=nameserver

def readXML():
 while 1==1:
	global error
	del NEWRANGES[:]
	lock.acquire()
	error=0
	tree = ET.parse('config.xml')
	root = tree.getroot()
	for net in root:
	 #parts=[]# TODO
	 liste=[]
	 #print net.tag, net.attrib
	 for child in net:
	  if child.tag =="prefix":
	   prefix = child.text
	  if child.tag =="prefix-len":
	   prefix_len = child.text
	  if child.tag =="version":
	   version = child.text
	  if child.tag =="forward":
	   forward = child.text
	  if child.tag =="dns":
	   dns = child.text
	  if child.tag =="mail":
	   mail = child.text
	  if child.tag =="ttl":
	   ttl = child.text
	  if child.tag =="nameserver":
	   nameserver = child.text.split(',')
	 if int(version)==6:
		 createAndAddIPv6(prefix,prefix_len,forward,dns,mail,ttl,nameserver)
	 if int(version)==4:
		createAndAddIPv4(prefix,prefix_len,forward,dns,mail,ttl,nameserver)
	
	if error==0:
		del RANGES[:]
		mycopy(NEWRANGES,RANGES)
		syslog.syslog('new data was NOT imported because their is an error in the XML File')
	lock.release()
	print >>sys.stdout, 'LOG\tsleep'
	time.sleep(10)






def base36encode(n):
    s = ''
    while True:
        n, r = divmod(n, len(DIGITS))
        s = DIGITS[r] + s
        if n == 0:
            break
    return s

def base36decode(s):
    n, s = 0, s[::-1]
    for i in xrange(0, len(s)):
        r = DIGITS.index(s[i])
        n += r * (len(DIGITS) ** i)
    return n



def parse(fd, out):
    line = fd.readline().strip()
    
    if not line.startswith('HELO'):
        print >>out, 'FAIL'
        out.flush()
        syslog.syslog('received "%s", expected "HELO"' % (line,))
        sys.exit(1)
    else:
        print >>out, 'OK\t%s ready' % (os.path.basename(sys.argv[0]),)
        out.flush()
        syslog.syslog('received HELO from PowerDNS')

    lastnet=0
    while True:
        line = fd.readline().strip()[::]
	lock.acquire()
        if not line:
            break

        #syslog.syslog('<<< %s' % (line,))
        #print >>out, 'LOG\tline: %s' % line

        request = line.split('\t')
        if request[0] == 'AXFR':
                if not lastnet == 0:
                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
                                (lastnet['forward'], 'IN', lastnet['ttl'], lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H'))
                        lastnet=lastnet
                        for ns in lastnet['nameserver']:
                                print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
                                        (lastnet['forward'], 'IN', lastnet['ttl'], ns)
                print >>out, 'END'
                out.flush()
                continue
        if len(request) < 6:
            print >>out, 'LOG\tPowerDNS sent unparsable line'
            print >>out, 'FAIL'
            out.flush()
            continue


        try:
                kind, qname, qclass, qtype, qid, ip = request
        except:
                kind, qname, qclass, qtype, qid, ip, their_ip = request
        #debug
        #print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< qid>>%s<< ip>>%s<<' % (qname, qtype, qclass, qid, ip)

        if qtype in ['AAAA', 'ANY'] and qname.startswith('node-'):
            print >>out, 'LOG\twe got a AAAA query'
            for range, key in enumerate(RANGES):
                if qname.endswith('.%s' % (key.forward,)) and int(key.version) == 6:
                    node = qname[5:].replace('.%s' % (key.forward,), '')
		    if node=='0':
                        ipv6 = netaddr.IPAddress(long(key.value))
                        print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t-1\t%s' % \
                            (qname, qclass, int(key.ttl), ipv6)
                    	break
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv6 = netaddr.IPAddress(long(key.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t-1\t%s' % \
                            (qname, qclass, int(key.ttl), ipv6)
                    break
        if qtype in ['A', 'ANY'] and qname.startswith('node-'):
            #print >>out, 'LOG\twe got a A query'
            for range, key in enumerate(RANGES):
                if qname.endswith('.%s' % (key.forward,)) and int(key.version) == 4:
                    node = qname[5:].replace('.%s' % (key.forward,), '')
		    if node=='0':
		    	ipv4 = netaddr.IPAddress(long(key.value) )
                        print >>out, 'DATA\t%s\t%s\tA\t%d\t-1\t%s' % \
                            (qname, qclass, int(key.ttl), ipv4)
                    	break
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv4 = netaddr.IPAddress(long(key.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tA\t%d\t-1\t%s' % \
                            (qname, qclass, int(key.ttl), ipv4)
                    break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            try:
                ipv6 = netaddr.IPAddress(ipv6)
            except:
                ipv6 = netaddr.IPAddress('::')
            for range, key in enumerate(RANGES):
                #debug
                #print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< TTL>>%s<<' % (qname, qtype, qclass, TTL)
                if ipv6 in key:
                    node = int(ipv6 - int(key.value))
                    node = base36encode(node)
                    print >>out, 'DATA\t%s\t%s\tPTR\t%d\t-1\tnode-%s.%s' % \
                        (qname, qclass, int(key.ttl), node, key.forward)
                    break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            for range, key in enumerate(RANGES):
                #debug
                #print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< TTL>>%s<<' % (qname, qtype, qclass, TTL)
                if ipv4 in key:
                    node = int(ipv4 - key.value)
                    node = base36encode(node)
                    print >>out, 'DATA\t%s\t%s\tPTR\t%d\t-1\tnode-%s.%s' % \
                        (qname, qclass, int(key.ttl), node, key.forward)
                    break

#        if qtype in ['SOA', 'ANY'] and qname.endswith('.ip6.arpa'):
#           #print >>out, 'LOG\twe got a SOA query for %s' % qname
#            ptr = qname.split('.')[:-2][::-1]
#            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
#            try:
#               ipv6 = netaddr.IPAddress(ipv6)
#           except:
#               ipv6 = netaddr.IPAddress('::')
#            for range, key in RANGES.iteritems():
#               #print >>out, 'LOG\tin for'
#               #print >>out, 'LOG\trange is %s' % range
#               #print >>out, 'LOG\tkey is %s' % key
#               if qname == key['domain']:
#                       print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                               (key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#                       lastnet=key
#                       break
#               if ipv6 in range:
#                       #print >>out, 'LOG\tipv6 is in range'
#                       print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                                       (key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#                       lastnet=key
#                       break
#       #print >>out, 'LOG\twe reached the end of IF clauses'
#
#        if qtype in ['SOA', 'ANY'] and qname.endswith('.in-addr.arpa'):
#           #print >>out, 'LOG\twe got a SOA query for %s' % qname
#            ptr = qname.split('.')[:-2][::-1]
#           ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
#            try:
#               ipv4 = netaddr.IPAddress(ipv4)
#           except:
#               ipv4 = netaddr.IPAddress('127.0.0.1')
#            for range, key in RANGES.iteritems():
#               #print >>out, 'LOG\tin for'
#               #print >>out, 'LOG\trange is %s' % range
#               #print >>out, 'LOG\tkey is %s' % key
#               if qname == key['domain']:
#                       print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                               (key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#                       lastnet=key
#                       break
#               if ipv4 in range:
#                       #print >>out, 'LOG\tipv4 is in range'
#                       print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                                       (key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#                       lastnet=key
#                       break
#       #print >>out, 'LOG\twe readed the end of IF clauses'

        if qtype in ['SOA', 'ANY', 'NS']:
                for range, key in enumerate(RANGES): # TODO
                        #print >>out, 'LOG\tkey domain: %s' % range.domain
                        #print >>out, 'LOG\tkey forward: %s' % key.forward
                        #print >>out, 'LOG\tqname: %s' % qname
                        if qname == key.domain:
                                if not qtype == 'NS':
                                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
                                                (key.domain, qclass, int(key.ttl), key.dns, key.email, time.strftime('%Y%m%d%H'))
                                        lastnet=key
                                if qtype in ['ANY', 'NS']:
                                        for ns in key.nameserver:
                                                print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
                                                        (key.domain, qclass, int(key.ttl), ns)
                                break
                        elif qname == key.forward:
                                if not qtype == 'NS':
                                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
                                                (key.forward, qclass, int(key.ttl), key.dns, key.email, time.strftime('%Y%m%d%H'))
                                        lastnet=key
                                if qtype in ['ANY', 'NS']:
                                        for ns in key['nameserver']:
                                                print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
                                                        (key.forward, qclass, int(key.ttl), ns)
                                break
	lock.release()
        print >>out, 'END'
        out.flush()

    syslog.syslog('terminating')
    return 0

if __name__ == '__main__':
    import sys
	
    start_new_thread(readXML,())
	#readXML()
	
    sys.exit(parse(sys.stdin, sys.stdout))
