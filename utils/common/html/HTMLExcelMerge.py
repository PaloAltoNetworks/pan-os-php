# HTML to XLS Merger script
# Designed to work with autoreporter.sh - ensure this file exists in the same directory as autoreporter.sh when run
# This script is intended to scan the output directories of autoreporter.sh and combine the HTML files into a single Excel workbook
# with multiple tabs for ease of reading.

import os, re
import pandas as pd
import sys


filepath = sys.argv[1]+'/'
excelfilename = sys.argv[2]

cwd = os.path.dirname(filepath)


print("Found directory "+cwd)
excelfile = pd.ExcelWriter(f'{cwd}/{excelfilename}', engine='xlsxwriter')
print("Creating excel file "+str(excelfile)+" in directory "+cwd)
excelfile
with pd.ExcelWriter(excelfile) as writer:
	for file in os.scandir(cwd):
		if file.name.endswith('.html'):
			print("Found HTML file "+file.name+" in directory "+cwd)
			html_file = pd.read_html(f'{cwd}/{file.name}')
			shortname=file.name.strip(".html")
			print("Stripping text from "+str(shortname)+". Worksheet name is "+shortname)
			for df in html_file:
				print("Writing sheet "+shortname+" to workbook "+str(excelfile))
				df.to_excel(writer, sheet_name=shortname)