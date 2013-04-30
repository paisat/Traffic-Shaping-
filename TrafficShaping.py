import ConfigParser
import subprocess
import os.path
import socket
from optparse import OptionParser

def execCommand(cmd,interactive=False):
	try:
		if interactive:
			po=subprocess.Popen(cmd)
		
		else:
			po=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			po.stdin.close()
	
		po.wait()

	except KeyboardInterrupt:
		print "Interrupt"

	return po

def setDefaultGateway(config,defaultGWIP,site):
	
	sites=config.items(site)
	for ip in sites:
		print "Setting %s as default gateway for %s ..."%(defaultGWIP,ip[1])
		
		interface=getInterfaceFromIP(ip[1])
		
		if interface==1:
			return 1

		cmd=['ssh','root@'+ip[1],'route','add','default','gw',defaultGWIP,interface]
		ret=execCommand(cmd)

		if ret.returncode==0:
			print "default gateway set "
		else:
			errMsg=ret.stderr.read().replace('\n','')
			if errMsg=="SIOCADDRT: File exists":
				print "default gateway already set"
			else:
				print errMsg
				return 1	
		
		print '\n'

	return 0


def enableNAT(config):
        
	interface=[]
	gatewayIP=['ip1','ip2']

        for ip in gatewayIP:
		inter=getInterfaceFromIP(config.get('GATEWAY',ip))
		if inter==1:
			return 1
                interface.append(inter)

	ipADD=config.get('GATEWAY',gatewayIP[0])

	cmd=['ssh','root@'+ipADD,'sysctl','-w','net.ipv4.ip_forward=1']
	ret=execCommand(cmd)
	if ret.returncode!=0:
		print ret.stderr.read()
		return 1
	
	cmd=['ssh','root@'+ipADD,'iptables','-t','nat','-A','POSTROUTING','-o',interface[0],'-j','MASQUERADE']
	
	ret=execCommand(cmd)
        if ret.returncode!=0:
                print ret.stderr.read()
		return 1

	cmd=['ssh','root@'+ipADD,'iptables','-A','FORWARD','-i',interface[0],'-o',interface[1],'-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT']
	
	ret=execCommand(cmd)
        if ret.returncode!=0:
                print ret.stderr.read()
		return 1

	cmd=['ssh','root@'+ipADD,'iptables','-A','FORWARD','-i',interface[1],'-o',interface[0],'-j','ACCEPT']
	
	ret=execCommand(cmd)
        if ret.returncode!=0:
                print ret.stderr.read()
		return 1


	return 0


def revertTrafficShaping(ip):
	
	interface=getInterfaceFromIP(ip)

	if interface==1:
		return 1
	cmd=['ssh','root@'+ip,'tc','qdisc','del','dev',interface,'root']
	ret=execCommand(cmd)

	if ret.returncode!=0:
		errMsg=ret.stderr.read().replace('\n','')
		
		if errMsg=="RTNETLINK answers: No such file or directory":
			pass
	
		else:
			print errMsg
			return 1
	return 0


def revertDefaultGateway(gatewayIP,section):
	
	for sec in section:
		interface=getInterfaceFromIP(sec[1])
		if interface==1:
			return 1

		cmd=['ssh','root@'+sec[1],'route','del','default','gw',gatewayIP,interface]
		retVal=execCommand(cmd)

		if retVal.returncode!=0:
			errMsg=retVal.stderr.read().replace('\n','')
			if errMsg!='SIOCDELRT: No such process':
				return 1
			

	return 0
		


def setTrafficShapingParameteres(config,single,loss=None,delay=None):
	
				
	interface=getInterfaceFromIP(config.get('GATEWAY','ip1'))
	if interface==1:
		return 1

	cmd=['ssh','root@'+config.get('GATEWAY','ip1'),'tc','qdisc','add','dev',interface,'root','netem']

	if single==False:
		interface2=getInterfaceFromIP(config.get('GATEWAY','ip2'))
	        if interface2==1:
                	return 1

		cmd2=['ssh','root@'+config.get('GATEWAY','ip1'),'tc','qdisc','add','dev',interface2,'root','netem']

	if delay!=None:	
		print "Delay : %s \n"%(delay)
		delay=str(delay)+"ms"
		cmd.append('delay')
		cmd.append(str(delay))
		if single==False:
			cmd2.append('delay')
			cmd2.append(str(delay))

	if loss!=None:
		print "Loss : %s \n"%(loss)
		loss=str(loss)+"%"
		cmd.append('loss')
		cmd.append(str(loss))
		if single==False:
			cmd2.append('loss')
                        cmd2.append(str(loss))

	retval=revertTrafficShaping(config.get('GATEWAY','ip1'))

	if retval==1:
		return 1

	if single==False:
		retval=revertTrafficShaping(config.get('GATEWAY','ip2'))
		if retval==1:
 	               return 1	
	
	ret=execCommand(cmd)

	if ret.returncode!=0:
		print ret.stderr.read()
		return 1

	if single==False:
		ret=execCommand(cmd2)
        	if ret.returncode!=0:
	                print ret.stderr.read()
               		return 1

	
	return 0

def getInterfaceFromIP(ip):

	cmd=['ssh','root@'+ip,'netstat','-ie']
	p1=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	cmd=['grep','-B1',ip]
	p2=subprocess.Popen(cmd,stdin=p1.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	cmd=['head','-n1']	
	p3=subprocess.Popen(cmd,stdin=p2.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	cmd=['awk','{print $1}']
	p4=subprocess.Popen(cmd,stdin=p3.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	#cmd=['sed','s/://']
	#p5=subprocess.Popen(cmd,stdin=p4.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

	ret=p4.communicate()
	if not ret[0]=='':
		return ret[0].replace('\n','')
	else:
		print "Interface for IP %s could not be found "%(ip)
		return 1


def generatePublicKey():

	if not os.path.exists(os.path.expanduser("~/.ssh/id_rsa.pub")):

		print ".... PUBLIC KEY NOT PRESENT.GENERATING ....\n"
		cmd=['ssh-keygen','-t','rsa']
		ret=execCommand(cmd,True)

		if ret.returncode==0:
			print ".... PUBLIC KEY GENERATED .... \n"
			return 0
	
		print ret.stderr.read()
		print ".... PUBLIC KEY GENERATION FAILED ....\n"
		return 1

def checkPasswordLessSSHLogin(config,timeout):
		
	keyGenerated=False
	cmd=['ssh','-oBatchMode=yes','-oConnectTimeout='+timeout,'ip','echo hello']	
	sections=config.sections()
	print sections
	for sec in sections:

		if sec!='CONFIG':

			item=config.items(sec)

			for ip in item:
				
				print ".... CHECKING PASSWORDLESS SSH FOR SITE IP  %s .... \n" %(ip[1])
				del cmd[3]
				cmd.insert(3,"root@"+ip[1])
				ret=execCommand(cmd)

				if ret.returncode==0:
					print "SITE IP %s PASSWORDLESS SSH SET \n "%(ip[1])
				else:
					print "PASSWORDLESS SSH NOT SET \n"
					print ret.stderr.read()
				
					
					if not keyGenerated:
						retVal=generatePublicKey()
						keyGenerated=True
						if retVal==1:
							return 1				
				
					print ".... COPYING PUBLIC KEY .... \n"

					copyCmd=['ssh-copy-id','-i',os.path.expanduser('~/.ssh/id_rsa.pub'),'root@'+ip[1]]
					ret=execCommand(copyCmd,True)
					if ret.returncode==0:
						print "PUBLIC KEY COPIED \n"
					else:
						print "PUBLIC KEY COPY FAILED\n"
						return 1			
				
				print "--------------------------------------------------------\n"
	return 0


def checkIpAddress(items,section):
	
	error=0
	for ip in items:
		try:
			socket.inet_aton(ip[1])
		except socket.error,Argument:
			print "%s is not a valid IP Address in section %s"%(ip[1],section)
			error=1

	return error			

def revert(config):
       
		
	print ".... REVERTING DEFAULT GATEWAY ....\n"
	ret=revertDefaultGateway(config.get('GATEWAY','ip1'),config.items('SITE 1'))

	if ret==1:
		return 1

	ret=revertDefaultGateway(config.get('GATEWAY','ip2'),config.items('SITE 2'))
	if ret==1:
		return 1
	print ".... DEFAULT GATEWAY REVERTED ....\n"
	print ".... REVERTING TRAFFIC SHAPING ....\n"

	ret=revertTrafficShaping(config.get('GATEWAY','ip1'))
	if ret==1:
		return 1
	ret=revertTrafficShaping(config.get('GATEWAY','ip2'))

	print ".... TRAFFIC SHAPING PARAMETERES REVERTED \n"
			
			
	return 0;			



def checkConfigFile(config,options):

	error=0;

	checkConfigSection=True

        if options.delay!=None or options.loss!=None:
                checkConfigSection=False

	if checkConfigSection:
		
		expectedSections=['SITE 1','SITE 2','GATEWAY','CONFIG']
	else:
		expectedSections=['SITE 1','SITE 2','GATEWAY']

	sections=config.sections()

	if len(sections)<3 or len(sections)>4  :
		print "Config file should have at least %d sections . Please read README for example config \n"%len(expectedSections)
		error=1
	else:

		for expectedSec in expectedSections:

			if not config.has_section(expectedSec) :
				print "%s section missing in config file\n"%(expectedSec)
				error=1
                	else:
				if expectedSec=='CONFIG':
					if len(config.items(expectedSec))==0:
						print "Mention at least one parameter delay or loss\n"
						error=1
					else:
						if (not config.has_option(expectedSec,'delay')) and (not config.has_option(expectedSec,'loss')):
							print "Specify at least one parameter delay or loss \n"
						else:
							try:
								if config.has_option(expectedSec,'delay'):
									delay=config.getint(expectedSec,'delay')
								if config.has_option(expectedSec,'loss'):
									loss=config.getint(expectedSec,'loss')
							except ValueError,Argument:
								print "delay and loss values should be a Integer"
								error=1
						 

				else:
					if expectedSec=='GATEWAY'and len(config.items(expectedSec))!=2 :
							print "%s section should have 2 IP ADDRESS\n"%(expectedSec)
							error=1
					if expectedSec=='GATEWAY' and len(config.items(expectedSec))==2:
							if not config.has_option('GATEWAY','ip1'):
								print "GATEWAY section should have ip1\n"
								error=1
							if not config.has_option('GATEWAY','ip2'):
								print "GATEWAY section should have ip2\n"
								error=1
 
					elif len(config.items(expectedSec))==0: 
						print "%s section should have at least 1 IP ADDRESS \n "%(expectedSec)
						error=1
					else:
						error=checkIpAddress(config.items(expectedSec),expectedSec) 
	return error
					

	

	
def main():
	
	usage="usage : %prog [options] arg"
	parser=OptionParser(usage)
	parser.add_option("-c","--config",dest="filename",help="Specifies config file . if not set searches for file named config in current folder",default="config");
	parser.add_option("-r","--revert",dest="revert",help="Reverts default gateway and traffic shaping parameteres",action="store_true")
	parser.add_option("-d","--delay",dest="delay",help="Specifies delay in ms . if this option is set then the value specified in config file is ignored",type="int")
	parser.add_option("-l","--loss",dest="loss",help="Specifies packet loss  . if this option is set then the value specified in config file is ignored",type="int")
	parser.add_option("-t","--timeout",dest="timeout",help="Specifies timeout for ssh commands . default 5 seconds",type="int",default=5)
	parser.add_option("-s","--single",dest="single",help="When set to true ,applies traffic shaping parameteres for only one interface in gateway",action="store_true",default=False)	
	(options,args)=parser.parse_args()


	if not os.path.exists(options.filename):
		print "config file not found"
		

	else:
		config=ConfigParser.RawConfigParser()
		config.read(options.filename)
		retVal=checkConfigFile(config,options)
		
		if retVal==0 and options.revert:
			revert(config)

		elif retVal==0 and not options.revert:	
			ret=checkPasswordLessSSHLogin(config,str(options.timeout))

			gatewayIP=['ip1','ip2']
			sections=['SITE 1','SITE 2']
		
			if ret==0:
				failed=0	
				print ".... SETTING DEFAULT GATEWAY .....\n"
				
				for ip,sec in zip(gatewayIP,sections):
					ret=setDefaultGateway(config,config.get('GATEWAY',ip),sec)
					if ret==1:
						failed=1	
						break
				if failed==0:
					print ".... DEFAULT GATEWAY SET ....\n"
					print ".... ENABLING NAT ON GATEWAY ....\n"
					ret=enableNAT(config)

					if ret==0:
						print ".... NAT ENABLED ....\n" 
						print ".... SETTING PARAMETERES ....\n"
						
						loss=None
						delay=None
						
						if options.delay!=None or options.loss!=None:
							if options.delay!=None:
								delay=options.delay
							if options.loss!=None:
								loss=options.loss
						else:
							if config.has_option('CONFIG','loss'):
								loss=config.getint('CONFIG','loss')
							
							if config.has_option('CONFIG','delay'):
								delay=config.getint('CONFIG','delay')	
						
						ret=setTrafficShapingParameteres(config,options.single,loss,delay)
						if ret==0:
							print ".... PARAMETERES SET ....\n" 


if __name__=="__main__":
	main()
