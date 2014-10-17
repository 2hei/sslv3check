sslv3check
==========

check sslv3 protocol leak

1. Something needed:

(1) timeout command needed.

Ubuntu/Debian: 
  apt-get install timeout  
  
CentOS:
  Download timeout rpm for CentOS5.x:
  wget ftp://ftp.pbone.net/mirror/ftp5.gwdg.de/pub/opensuse/repositories/home:/crt0solutions:/extras/CentOS_CentOS-5/x86_64/timeout-8.4-20.3.crt0.x86_64.rpm
  
  rpm -ivh timeout-8.4-20.3.crt0.x86_64.rpm 

(2) Python2.6+ ENV


2. Usage:
python sslv3_leak_check.py

The script use command to check sslv3 protocol:
# openssl s_client -connect <ip>:<port> -ssl3

3. Check result:
ip list of sslv3 leak output file: 
  sslv3ips
good iplist of sslv3 output file: 
nosslv3ips

