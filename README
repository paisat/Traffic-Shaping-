Traffic-Shaping-
================

Script helps in setting delay and loss parameters using tc command and it can be used for Traffic shaping

Config File Format
=================
[SITE 1]
ip1=10.70.42.224
ip2=10.70.42.225

[SITE 2]
ip1=10.70.42.226
ip2=10.70.42.227

[GATEWAY]
ip1=10.70.42.228
ip2=10.70.42.230

[CONFIG]
delay=10

-----
SITE 1,SITE 2 Section can have one or more ip address
GATEWAY should have exactly 2 ip Address
First ip Address in GATEWAY is set as default gateway for all IPS in SITE 1
Second ip Address in GATEWAY is set as default gateway for all IPS in site 2
CONFIG section should have atleast one parameter delay or loss . The parameteres should be int 


Commands 
================

Usage: usage : TrafficShaping.py [options] arg

Options:
  -h, --help            show this help message and exit
  -c FILENAME, --config=FILENAME
                        Specifies config file . if not set searches for file
                        named config in current folder
  -r, --revert          Reverts default gateway and traffic shaping
                        parameteres
  -d DELAY, --delay=DELAY
                        Specifies delay in ms . if this option is set then the
                        value specified in config file is ignored
  -l LOSS, --loss=LOSS  Specifies packet loss  . if this option is set then
                        the value specified in config file is ignored
  -t TIMEOUT, --timeout=TIMEOUT
                        Specifies timeout for ssh commands . default 5 seconds
  -s, --single          When set to true ,applies traffic shaping parameteres
                        for only one interface in gateway
                        

--revert option reverts default gateway and traffic shaping parameteres 
                        

Commands used
=================

        COMMAND USED FOR TO CHECK PASSWORDLESS SSH LOGIN : ssh -oBatchMode=yes -oConnecttimeout=5 <ip> 'echo hello'
        
        COMMAND USED TO SET DEFAULT GATEWAY : route add default gw <ip> <interface>
        
        COMMAND USED TO ENABLE NAT : iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        
                                     iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
                                     
                                     iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
                                     
        COMMAND USED TO GET INTERFACE FROM IP : netsat -ie|grep -B1 <ip>| head -n1| awk '{print $1}'
        
        COMMAND USED TO SET TRAFFIC SHAPING PARAMETERES : tc qdisc add dev <interface> root netem delay 10ms loss 10%
        
        COMMAND USED TO REVERT TRAFFIC SHAPING : tc qdisc del dev <interface> root
        
        COMMAND USED TO REVERT DEFAULT GATEWAY : route del default gw <ip> <interface>
        
        
        
        
        
        
        
        
        
                                     
                                     
                                     
                

