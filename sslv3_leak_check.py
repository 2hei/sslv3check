#!/usr/bin/env python
#
# Script Name: sslv3_leak_check.py
# Author: fisherman
# Mail: yu2hei@163.com
# Date: 20141015
# Version: 1.0
 
import sys,re,subprocess,socket,struct
 
def mycommand(cmd):
    try:
        p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
    except:
        stdout = "null"
    return stdout.strip()

def ip2long(ip):
    longip = 0
    if not re.match("^(\d{1,3}\.){3}\d{1,3}$", ip):
        return None
    for q in ip.split('.'):
        longip = (longip << 8) + int(q)
    return(longip)

def long2ip(ip):
    return socket.inet_ntoa(struct.pack("!I", ip))

#not in use
def getip_range(mask):
    tag = 0
    subnet = []
    diff = 32 - mask
    while diff >= 8:
        diff = diff - 8
        subnet.append('8')
        tag = tag + 1
    subnet.append(diff)
    for i in xrange(0,4-len(subnet)):
        subnet.append(0)
    return subnet
 
if __name__ == "__main__":
    IDC_iplist = [
                  '172.16.100.0/24',
                  'xxx.xxx.xxx.xxx/28',
                  ]
    
    iplist = []
    ssl_ports = ['80','443','8080','8140','8192','16384']

    allips = file('allips','w')
    sslv3ips = file('sslv3ips','w')
    nosslv3ips = file('nosslv3ips','w')

    try:
        for line in IDC_iplist:
            startip,mask = line.split('/')[0],line.split('/')[1]
            if int(startip.split('.')[-1]) + 2 ** (32 - int(mask)) > 256:
                print "ip/mask ["+startip+"/"+mask+"] error, Script exit!"
                sys.exit(2)
            startipnum =  ip2long(startip)
            endipnum = startipnum + 2 ** (32 - int(mask))
            ipnum = 2 ** (32 - int(mask))
            for i in xrange(0,ipnum):
                iplist.append(long2ip(startipnum + i))            
    except Exception,ex:
        print "convert error",ex
    
    for i in iplist:
        allips.write(str(i)+'\n')
        for p in ssl_ports:
            print "checking port "+str(i).strip()+':'+str(p)
            check_sslv3_cmd = 'echo -n | /usr/bin/timeout 1 openssl s_client -connect '+str(i)+':'+str(p)+' -ssl3 2>&1 | egrep "Cipher is|handshake failure" '
            out = mycommand(check_sslv3_cmd)
            if re.search(r'Cipher',out):
                sslv3ips.write('IPAddress '+str(i)+':'+str(p)+' is sslv3 vulnerable.\n')
            elif re.search(r'handshake failure',out):
                nosslv3ips.write('IPAddress '+str(i)+':'+str(p)+' is sslv3 ok.\n')
            else:
                pass

    allips.close()
    sslv3ips.close()
    nosslv3ips.close()
