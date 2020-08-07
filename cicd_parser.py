import sys
import os
import getopt
import json

pfix = '[ThreadFix Policy Parser]'
# supported extensions
_supportedExtensions = ['.json']
_filetype = None

def __getOverallStatus(data):
	return 'Passing' if data['passing'] else 'Failing'

def __getPassing(data):
	return data['passed']
	
def __getFailing(data):
	return data['failed']

def __printVulnerabilitySummary(data):
	print(pfix, 'Vulnerability Summary:')
	print(pfix, '\t', 'Critical:', str(data['newCriticalTotal']) + '/' + str(data['criticalTotal']), '(new/existing)')
	print(pfix, '\t', 'High:', str(data['newHighTotal']) + '/' + str(data['highTotal']), '(new/existing)')
	print(pfix, '\t', 'Medium:', str(data['newMediumTotal']) + '/' + str(data['mediumTotal']), '(new/existing)')
	print(pfix, '\t', 'Low:', str(data['newLowTotal']) + '/' + str(data['lowTotal']), '(new/existing)')
	print(pfix, '\t', 'Informational:', str(data['newInfoTotal']) + '/' + str(data['infoTotal']), '(new/existing)')
	
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
			print(pfix, 'Application Status:', __getOverallStatus(data))
			
			if status:
				pass
			else:
				print(pfix, 'Failing policies:')
				for policy in __getFailing(data):
					print(pfix, '\t', policy['severity'] + ' maxAllowed: ' + str(policy['maxAllowed']) + ' maxIntroduced: ' + str(policy['maxIntroduced']))
			
			__printVulnerabilitySummary(data['snapshot']['vulnerabilitySummary'])
			
	if opt in ('-h', '--help'):
		print('help is not available, sorry...')