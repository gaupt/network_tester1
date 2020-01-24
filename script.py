
import os
import subprocess
import time
import nmap
banner = "\n\n WELCOME TO SCRIPT \n\n"
footer = "\n\n THE END \n\n"
print(banner)
ipaddr = input("Please enter a IP address:\n")    #add ip address host
vrf='management'
print(f'You entered {ipaddr}')
ping = 'ping {} {}'.format(ipaddr,vrf)
print(ping)
b=os.system("ping -c 50 " +ipaddr)
time.sleep(1)


#hostadd=input("Please enter IP and mask network (example: 192.168.1.0/24):\n")
nm = nmap.PortScanner()
nm.all_hosts()
hostadd=(ipaddr[:-2]) # last two number on IP address delete
nm.scan(hosts=hostadd+'0/24', arguments='-sP')  #arguments='-n -sP -PE -PA21,23,80,3389'
hosts_list=[(x,nm[x]['status']['state'])for x in nm.all_hosts()]
for host,status in hosts_list:
    print('{0}:{1}'.format(host,status))


print(footer)
