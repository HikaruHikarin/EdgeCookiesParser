#
#
#Script parses Cookies.binarycookies files from Chromium-based Edge browser for iOS                                                                               
#
#Written by Hika, based on Satishb3's BinaryCookieReader (http://www.securitylearn.net)         
#
#

import sys
from struct import unpack
from io import BytesIO
from time import strftime, gmtime

#Check initial arguments
 
if len(sys.argv)!=2:
	print ('Usage: python EdgeCookiesParser.py [Path to Cookies.binarycookies file]')
	sys.exit(0)
	
cookiesFilePath=sys.argv[1]

try:
	cookiesFile=open(cookiesFilePath,'rb')
except IOError as e:
	print (cookiesFilePath + ' doesn\'t exist')
	sys.exit(0)
   
#Check for correct magic byte

if str(cookiesFile.read(4))!= "b'cook'":
	print ('File format is not supported')
	sys.exit(0)
	
#Initialize an array of cookie pages

numberOfPages=unpack('>i',cookiesFile.read(4))[0]               
pageSizes = []
for num in range(numberOfPages):
	pageSizes.append(unpack('>i',cookiesFile.read(4))[0])  
	
pages = []
for size in pageSizes:
	pages.append(cookiesFile.read(size))                      

for page in pages:
	page = BytesIO(page)                                     
	page.read(4)                                            
	numberOfCookies = unpack('<i',page.read(4))[0]                
	cookiesOffset = []
	for num in range(numberOfCookies ):
		cookiesOffset.append(unpack('<i',page.read(4))[0]) 

	page.read(4)

#Parse individual cookie record

	cookie=''
	for offset in cookiesOffset:
		page.seek(offset)                                   
		size=unpack('<i',page.read(4))[0]             
		cookie=BytesIO(page.read(size))              
		cookie.read(4)

#Flags interpretation
		
		flagsCode = unpack('<i',cookie.read(4))[0]                
		flags = ''
		if flagsCode == 0:
			flags = ''
		elif flagsCode  == 1:
			flags = 'Secure'
		elif flagsCode == 4:
			flags = 'HttpOnly'
		elif flagsCode == 5:
			flags = 'Secure; HttpOnly'
		else:
			flags='Unknown'
			
		cookie.read(4)                                      
		
#Calculation of offsets from cookie's starting point

		urlOffset=unpack('<i',cookie.read(4))[0]            
		nameOffset=unpack('<i',cookie.read(4))[0]           
		pathOffset=unpack('<i',cookie.read(4))[0]           
		valueOffset=unpack('<i',cookie.read(4))[0]          	
		endOfCookie=cookie.read(8)

#Dates interpretation
		                        
		macEpoch= unpack('<d',cookie.read(8))[0]+978307200          
		expires=strftime("%a, %d %b %Y ",gmtime(macEpoch))[:-1] 
		unixEpoch=unpack('<d',cookie.read(8))[0]+978307200           
		created = strftime("%a, %d %b %Y ",gmtime(unixEpoch))[:-1]
		
#URL decoding

		cookie.seek(urlOffset - 4)                            
		url = ''
		u = cookie.read(1)
		while unpack('<b',u)[0]!=0:
			url=url+str(u.decode('UTF-8'))
			u=cookie.read(1)
				
#Name decoding

		cookie.seek(nameOffset-4)                           
		name = ''
		n = cookie.read(1)
		while unpack('<b',n)[0] != 0:
			name = name+str(n.decode('UTF-8'))
			n = cookie.read(1)
				
#Path decoding

		cookie.seek(pathOffset-4)                          
		path=''
		p=cookie.read(1)
		while unpack('<b',p)[0]!=0:
			path=path+str(p.decode('UTF-8'))
			p=cookie.read(1)
			
#Value decoding	
		cookie.seek(valueOffset-4)                         
		value=''
		v = cookie.read(1)
		while unpack('<b',v)[0]!=0:
			value=value+str(v.decode('UTF-8'))
			v=cookie.read(1)
		
#Printing the results

		print ('\nCookie: '+name+'='+value+'\nURL: ' + url + '\nPath: ' + path + '\nCreated: ' + created + '\nExpires: '+expires+'\nFlags: '+flags)
		
cookiesFile.close()