#!/usr/bin/python3

import sys
import xml.etree.ElementTree as xml

def parse_scan(nessus_file):

	# Open Nessus file 
	root = xml.parse(nessus_file).getroot()
    
	# Define CSV format
	header = ('Severity',
		'Host',
		'PluginID',
		'Protocol',
		'Port',
		'FQDN',
		'OS',
		'PluginName',
		'Description',
		'Solution')

	row_format = '"{}"'
	for i in range(len(header)-1):
		row_format += ';' + '"{}"'

	# Print CSV header
	print (row_format.format(*header))

	# Find the reporthost item	
	row_count = 0
	report = root.find('Report')

	for reporthost in report.findall('ReportHost'):

		# Collect host props and add host ip to host dict
		host = reporthost.get('name')

		hostprops = {}		
		for tag in reporthost.find('HostProperties').findall('tag'):
			hostprops[tag.get('name')] = tag.text

		# Get host report items
		for reportitem in reporthost.findall('ReportItem'):

			print (row_format.format(
				reportitem.attrib['severity'],
				host,
				reportitem.attrib['pluginID'],
				reportitem.attrib.get('protocol', '-'),
				reportitem.attrib.get('port', 0),
				hostprops.get('host-fqdn', '-'),
				hostprops.get('operating-system', '-'),
				reportitem.attrib['pluginName'],
				reportitem.findtext('description', default='-'),
				reportitem.findtext('solution', default='-')
			))
			row_count += 1

	return row_count

def print_err(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def main():
	try:
		nessus_file = sys.argv[1]
		print_err("Processed {} items of file: {}.".format(parse_scan(nessus_file), nessus_file))

	except IndexError:
		print_err("Usage: nessus2csv <nessus_file> - Print out Nessus report on standard output in CSV form.")
		return(1)

if __name__== "__main__":
	main()



