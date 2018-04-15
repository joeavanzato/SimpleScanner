# SimpleScanner
Basic XSS, SQLi and LFI Vulnerability Scanner

By: Joe Avanzato, joeavanzato@gmail.com

To-Do Plans: More robust crawling, better payload construction, additional SQLi detection such as BLIND, more customization for all scan parameters, false-positive metrics, DOM-based XSS and more...

This utility represents a naive attempt at vulnerability scanning for (currently) Reflected Cross Site Scripting (XSS), Error-Based SQL Injection and Local File Inclusions.  It is currently extremely simple/basic and likely returns a high false-positive rate depending upon the web-application being tested.

-H - Specify Web-Host for scanning, Use surrounding double-quotes if giving GET parameters
-P - Only check these POST parameters in XSS/SQL tests
-G - Only check these GET parameters in XSS/SQL tests
-X - Perform Reflected XSS Injection Testing
-S - Perform Error-Based SQL Injection Testing
-F - Form-Search - Use if supplying base-page rather than full GET request to SQL tests
-C - Enable site crawling
-D - Give depth 1-5 to determine overall recursiveness of site crawl

Example Commands known to work against OWASP BWA Mutillidae II

SQL Pre-Specified GET and Fuzz
Double-Quote necessary to avoid win cli confusion on commands

py basicscanner.py -S -F -H "http://IP/mutillidae/index.php?page=user-info.php&username=&password=&user-info-php-submit-button=View+Account+Details"

SQL Form-Search and Fuzz

py basicscanner.py -S -F -H http://IP/mutillidae/index.php?page=user-info.php

SQL form-Search, fuzz, crawl depth 3

py basicscanner.py -S -F -C -D 3 -H "http://IP/mutillidae/"

XSS Fuzz

py basicscanner.py -X -H http://IP/mutillidae/index.php?page=user-info.php

XSS with crawling depth 2

py basicscanner.py -X -C -D 2 -H http://IP/mutillidae/index.php?page=user-info.php

LFI Testing on single parameter
py basicscanner.py -L -H http://IP/mutillidae/index.php?page=

