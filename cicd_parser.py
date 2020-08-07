import sys
import os
import getopt
import json

pfix = '[ThreadFix Policy Parser] '
# supported extensions
_supportedExtensions = ['.json']
_filetype = None

def __getOverallStatus(data):
	return 'Passing' if data['passing'] else 'Failing'

def __getPassing(data):
	return data['passed']
	
def __getFailing(data):
	return data['failed']
def __printFailing(data):
	failing = __getFailing(data)
	
	hasCrit = False
	critAll = None 
	critNew = None
	hasHigh = False
	highAll = None 
	highNew = None
	hasMed = False
	medAll = None 
	medNew = None
	hasLow = False
	lowAll = None 
	lowNew = None
	hasInfo = False
	infoAll = None 
	infoNew = None
	for policy in failing:
		if 'Critical' == policy['severity']:
			critNew = policy['maxIntroduced']
			critAll = policy['maxAllowed']
			hasCrit = True
		if 'High' == policy['severity']:
			highNew = policy['maxIntroduced']
			highAll = policy['maxAllowed']
			hasHigh = True
		if 'Medium' == policy['severity']:
			medNew = policy['maxIntroduced']
			medAll = policy['maxAllowed']
			hasMed = True
		if 'Low' == policy['severity']:
			lowNew = policy['maxIntroduced']
			lowAll = policy['maxAllowed']
			hasLow = True
		if 'Info' == policy['severity']:
			infoNew = policy['maxIntroduced']
			infoAll = policy['maxAllowed']
			hasInfo = True
	print(pfix + 'Failing policies:')
	print(pfix + '\tSeverity\tMax Allowed\tMax Introduced')
	print(pfix + '----------------------------------------------------')
	if hasCrit:
		print(pfix + '\tCritical\t' + str(critAll) + '\t\t' + str(critNew))
	if hasHigh:
		print(pfix + '\tHigh\t\t' + str(highAll) + '\t\t' + str(highNew))
	if hasMed:
		print(pfix + '\tMedium\t\t' + str(medAll) + '\t\t' + str(medNew))
	if hasLow:
		print(pfix + '\tLow\t\t' + str(lowAll) + '\t\t' + str(lowNew))
	if hasInfo:
		print(pfix + '\tInfo\t\t' + str(infoAll) + '\t\t' + str(infoNew))
	
def __printVulnerabilitySummary(data):
	print(pfix + 'Vulnerability Summary:(new/existing)')
	print(pfix + '----------------------------------------------------')
	print(pfix + '\tCritical: \t' + str(data['newCriticalTotal']) + '/' + str(data['criticalTotal']))
	print(pfix + '\tHigh: \t\t' + str(data['newHighTotal']) + '/' + str(data['highTotal']))
	print(pfix + '\tMedium: \t' + str(data['newMediumTotal']) + '/' + str(data['mediumTotal']))
	print(pfix + '\tLow: \t\t' + str(data['newLowTotal']) + '/' + str(data['lowTotal']))
	print(pfix + '\tInformational: \t' + str(data['newInfoTotal']) + '/' + str(data['infoTotal']))
	
aOpts = ['-h', 'help', '-e']
opts, args = getopt.getopt(sys.argv[1:],'he', aOpts)
for opt, arg in opts:
	if opt in ('-e', '--evaluate'):
		data = None
		inFile = args[0]
		if inFile is None:
			print(pfix,'--no response json from the ThreadFix server to evaluate--')
			sys.exit(1)
		filepath = os.path.abspath(inFile)
		fileName, extension = os.path.splitext(filepath)
		if extension in _supportedExtensions:
			_filetype = extension.replace('.', '')
		with open(filepath, 'r') as f:
			data = json.load(f)
		if data is not None:
			data = data['object']
			status = data['passing']
			print(pfix + 'Application Status: ' + __getOverallStatus(data))
			
			if status:
				__printVulnerabilitySummary(data['snapshot']['vulnerabilitySummary'])
			else:
				__printFailing(data)
				
				__printVulnerabilitySummary(data['snapshot']['vulnerabilitySummary'])
				sys.exit(2)
	if opt in ('-h', '--help'):
		print('help is not available, sorry...')