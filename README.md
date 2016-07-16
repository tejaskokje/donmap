DESCRIPTION
-----------
DO-nmap is Definitely Outstanding Network Mapper. "DO" also stands for the initials of the company for which this tool was written as part of the interview process.

DO-nmap can scan TCP ports on a given hostname/IP address. 

AUTHOR
------
Tejas Kokje
tejas.kokje@gmail.com

FEATURES
--------
* Supports scanning of all the TCP ports or range of ports.
* Supports scanning for a given FQDN hostname or IP address.
* Supports scanning of TCP ports on all hosts in a given IPv4 subnet.
* Supports TCP port scanning for IPv6 hosts.
* Provides options to change connection timeout and scanning threads.

LIMITATIONS
----------
* No support for UDP port scanning.
* No support for IPv6 subnet scanning.
* Uses connect() to scan the ports. Hence TCP three-way handshake has to complete before detecting active port. This approach
  is slower than just declaring port to be active when SYN+ACK is received.

BUILD
-----
To build DO-nmap, simply issue "make" 
	shell# make
	gcc -Wall -Werror   -c donmap.c
	gcc -Wall -Werror   -c donmap_worker.c
	gcc -Wall -Werror   donmap.o donmap_worker.o -lpthread -o donmap

You will need pthread library and GNU gcc to build DO-nmap.

After build is successful, you should have a 'donmap' binary in current working directory.

USAGE
-----
Usage: donmap [options]
OPTIONS:

         -? : Print this help string.
         
         -6 : Use IPv6 for layer 3 communication (default is IPV4).
         
         -f : First port to start the scan. Number should be between 1 and 65535.
         
         -h : Print this help string.
         
         -l : Last port to finish the scan. Number should be between 1 and 65535.
         
         -n : Do not resolve port numbers to services in results.
         
         -s : Scan all addresses in the subnet. Input should be in CIDR format.
              E.g. 192.168.1.0/24. This option cannot be used with -t option.
              
         -p : Number of threads that will run in parallel. Number should be between
              1 and 16 (default is 8).
              
         -t : Target host to scan ports. This option cannot be used with -n option.
              If both -t and -n options are missing, localhost is scanned for open ports.
              
         -w : Wait time in milliseconds before connection timeout. Number should be between
              1 and 10000 (default is 400).
EXAMPLES:

To scan www.google.com from TCP ports 20 to 100 with timeout value of 40 milliseconds
using 4 threads in parallel, use following command
         donmap -w 40 -f 20 -l 100 -p 4 -t www.google.com
         

To scan 192.168.0.0/16 for all TCP ports with output only displaying numeric ports use
following command
         donmap -s 192.168.0.0/16 -n
         

To scan www.facebook.com for TCP ports 20 to 4096 with IPv6 address and timeout value of
100 milliseoonds, use following command
         donmap -6 -t www.facebook.com -f 20 -l 4096 -w 100
        
LICENSE
------

All rights reserved. Please find simplified BSD LICENSE file in this directory.
