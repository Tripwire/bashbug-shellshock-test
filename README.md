bashbug-shellshock-test
=======================

This offline tool is not supported and is provided for informational purposes only. 
This tool is dependent on Python 2.7.

'''
'
' Shellshock Test - CVE-2014-6271
' Written by Tripwire VERT (http://www.tripwire.com/vert)
' 
' This offline tool is not supported and is provided for informational purposes only.
' This tool uses Python - license information is available here: http://opensource.org/licenses/Python-2.0
'
'''


usage: shellshock_test.py [-h] [--path [PATH]] [--paths [PATHS]]
                          [--target [TARGET]] [--targets [TARGETS]]
                          [--spider [SPIDER]] [--url [URL]] [--log [LOG]]
                          [--ssl [SSL]]
                          {local,remote}
                          
Contains two modes of operation:

local - requires no arguments, tests the local bash prompt for CVE-2014-6271.

remote - two test methods, requires additional options. Tests an HTTP Server for CVE-2014-6271.
    
    Method 1:
    --path / --paths - Specify a single path via command line or a path-per-line file of paths to test. 
    --target / --targets - Specify a single target via command line or a target-per-line file of targets to test. [Format: ip:port]
    
    Method 2:
    --spider - Specify a local file path to pull file names from to test. 
    --url -- Specify the url to append the local file names to. 
    
Additional options:
--ssl - Test hosts via SSL
--log - Enable logging to a file rather than stdout

*Note that this script only returns vulnerable matches*

Additional information available from: http://www.tripwire.com/vert/shellshock-bash-bug/
