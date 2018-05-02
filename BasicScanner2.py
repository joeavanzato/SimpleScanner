#Basic Vulnerability Scanner - Local File Inclusion, Basic SQLI, Basic Reflected XSS
#By: Joe Avanzato, joeavanzato@gmail.com
#Ensure 'xss.txt', 'lfidot.txt', 'lfislash.txt', 'sql.txt' exist in same directory as script execution
#Requires Python 3.6+ and the installation of (BeautifulSoup4, Requests) Modules (py -m pip install Beautifulsoup4, Requests)

#TO-DO: Lots..
#Increase robustness for form detection, reduce false positives, use set GET/POST to filter keys in SQL/XSS tests/only test specific variables, increase LFI algorithm dynamicness, add testing for BLIND/non-error based SQL Injection..
#..Add tests for potential stored/DOM based XSS, custom depth settings for LFI, custom LFI 'goals' instead of simply /etc/passwd, 

import requests #third party
#import sys
import datetime
import time
import argparse
import os
import bs4 #third party
import re
import urllib

parser = argparse.ArgumentParser(usage = '\n--Page (-H) [Scan-Target]\n--Post (-P) [Specify POST Parameters to check for SQL Injection]\n --Get (-G) [Specify GET parameters to check for SQL Injection]\n --xss (-X) [Enable Reflected Cross Site Scripting Tests]\n --lfi (-L) [Enable Local File Inclusion Tests]\n --sql (-S) [Enable SQL Injection Tests]\n --formsearch (-F) [Enable Form-Searching]\n --crawl (-C) [Enable Page Crawling]\n --depth (-D) [Specify Optional Crawl Depth]')
parser.add_argument("-H", "--Page", help='Specify FQDN Page for Scanning (If using -S, supply entire URL encased in double-quotes ex. "http://localhost?page=test&username=test&passaword=test", If using -X, only base page needed, If using -S supply entire GET request for desired SQL Fuzzing)', required = True)
parser.add_argument("-P", "--Post", help='Specify POST parameters to check for SQL Injection (Example: \'Key1, Key2\')', nargs="+")
parser.add_argument("-G", "--Get", help='Specify GET parameters to check for SQL Injection (Example: Key1, Key2)', nargs="+")
parser.add_argument("-X", "--xss", help='Enable Reflected XSS Checking', action='store_true')
parser.add_argument("-S", "--sql", help='Enable SQL Injection Checking', action='store_true')
parser.add_argument("-L", "--lfi", help='Enable Local File Inclusion Checking; Insure Host Points to exact traversal location i.e. \'localhost/index.php?page=\' (Does not yet work in combination with crawling)', action='store_true')
parser.add_argument("-F", "--formsearch", help='Enable Form Searching; Do not use when supplying URI that includes parameters beyond page', action='store_true')
parser.add_argument("-C", "--crawl", help='Enable Page Crawling to Discover Forms on sub-pages', action='store_true')
parser.add_argument("-D", "--depth", help='Specify Crawling Depth 1-5 (1 = Base Only, 2 = Base + Check Links on Base, etc)', nargs=1)
args = parser.parse_args()

if (args.Post is not None) and (args.Get is not None):
    print("Select only POST or GET Parameters, Not Both!")
    exit(0)

#global host
#host = args.Page
current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")


def main():
    #global response_data
    #global response_text

    if args.Post is not None: #Custom POST parameters included
        print(args.Post)
        #post_data = []
        #for i in args.Post:
            #a, b = i.split(":")
            #print(a)
            #print(b)
            #i = "'"+a+"': '"+b+"'"
            #print(i)
            #post_data.append(i)
        #print(post_data)
        #post_data=str(post_data).replace("[", "").replace("]", "").replace("\"", "")
        #pdata = "{"+post_data+"}"
        #print(pdata)
        
        #response_data = requests.post(host, data=pdata)
        #response_text = response_data.text
        #print(response_text)
    else:
        print("POST Parameters Not Set")
        pass
    if args.Get is not None: #Custom GET parameters included
        print(args.Get)
        #get_data=str(args.Get).replace("[", "").replace("]", "")
        #data = "{"+get_data+"}"
        #print(data)
        #response_data = requests.get(host, params=data)
        #print(response_data)
        #response_text = response_data.text
        #print(response_text)
    else:
        print("GET Parameters Not Set")
        #pass

    path_test()

def path_test(): #Initial HTML GET for target page, initiates further test based on flags set
    #global response_text
    host = args.Page
    print("Testing : "+host)

    #print(args.xss)
    #print(args.sql)
    #response_data = requests.get(host)
    #response_text = response_data.text
    #print(response_text)

    if (args.crawl == True):
        print("Crawling Host for Links / Forms")
        crawl(host)
    else:
        print("Skipping Crawl Functionality..")

    if (args.xss == True) and (args.crawl == True):
        for host in link_list:
            xss_test(host)
            print("\n"+"======== List of potential XSS Injections for "+host+" ========"+"\n")
            print(str(potential_xss))
            filename = "XSS_DETECTIONS_"+current_datetime+".txt"
            if os.path.exists(filename):
                write_style = 'a'
            else:
                write_style = 'w'
            f = open(filename, write_style)
            f.write("Detection for HOST : "+host+"\n")
            for xss in potential_xss:
                f.write(xss+"\n")
            f.close()
    elif (args.xss == True) and (args.crawl == False):
        xss_test(host)
        print("\n"+"======== List of potential XSS Injections ========"+"\n")
        print(str(potential_xss))
        filename = "XSS_DETECTIONS_"+current_datetime+".txt"
        if os.path.exists(filename):
            write_style = 'a'
        else:
            write_style = 'w'
        f = open(filename, write_style)
        f.write("Detection for HOST : "+host+"\n")
        for xss in potential_xss:
            f.write(xss+"\n")
        f.close()
    else:
        print("Skipping Reflected-XSS Checks")

    if (args.sql == True) and (args.crawl == True):
        for host in link_list:
            sql_test(host)
            print("\n"+"======== List of potential SQL Injections for "+host+" ========"+"\n")
            print(str(potential_sql))
            filename = "SQL_DETECTIONS_"+current_datetime+".txt"
            if os.path.exists(filename):
                write_style = 'a'
            else:
                write_style = 'w'
            f = open(filename, write_style)
            f.write("Detection for HOST : "+host+"\n")
            for sql in potential_sql:
                f.write(sql+"\n")
            f.close()
    elif (args.sql == True) and (args.crawl == False):
        sql_test(host)
        print("\n"+"======== List of potential SQL Injections ========"+"\n")
        print(str(potential_sql))
        filename = "SQL_DETECTIONS_"+current_datetime+".txt"
        if os.path.exists(filename):
            write_style = 'a'
        else:
            write_style = 'w'
        f = open(filename, write_style)
        f.write("Detection for HOST : "+host+"\n")
        for sql in potential_sql:
            f.write(sql+"\n")
        f.close()
    else:
        print("Skipping SQL Injection Tests")

    if (args.lfi == True):
        lfi_test(host)
        filename = "LFI_DETECTIONS_"+current_datetime+".txt"
        if os.path.exists(filename):
            write_style = 'a'
        else:
            write_style = 'w'
        f = open(filename, write_style)
        f.write("Detection for HOST : "+host+"\n")
        for lfi in lfi_win:
            f.write(lfi+"\n")
        f.close()
    else:
        print("Skipping LFI Tests")

def xss_test(host): #Reads Reflected XSS payloads from 'xss.txt', scrapes HTML to detect all forms on page, iterates through payloads and forms to attempt XSS injection, reads response to look for payload
    global potential_xss
    response_data = requests.get(host, verify=False)
    response_text = response_data.text
    potential_xss = []
    file = open("xss.txt")
    xss_tests = file.readlines()
    try:
        host_base, host_ext = host.split('?')
        host_base = host_base + "?"
    except:
        host_base = host
        pass
    print("BASE URL :"+host_base)
    print("Initiating Cross Site Scripting (XSS) Tests...")
    parse = bs4.BeautifulSoup(response_text, 'html.parser')
    all_forms = parse.find_all('form')
    for payload in xss_tests:
        #testload = "<script>alert(\"KOALA\")</script>"
        #parse = bs4.BeautifulSoup(response_text, 'html.parser')
        #all_forms = parse.find_all('form')
        #all_forms = all_forms + parse.find_all('select')
        if len(all_forms) == 0:
            print("No HTML Forms Detected!")
            break
        else:
            testload = payload.strip()
            print("Current Payload = "+testload)
            for form in all_forms:
                #print(form)
                if (("name=\"username\"") or ("name=\"name\"") or ("name=\"user\"") or ("name=\"client\"") or ("name=\"account\"") or ("name=\"accountname\"") or ("name=\"id\"") or ("name=\"userid\"") or ("name=\"query\"") or ("name=\"search\"") or ("name=\"textfile\"") or ("name=\"file\"") in form) or (1 == 1):
                    login_form = form
                    #print("Username Field found in current form!")
                    login_action = login_form.get('action')
                    login_method = login_form.get('method')
                    form_fields = form.findAll('input')
                    form_fields = form_fields + form.findAll('select')
                    form_data = dict( (field.get('name'), field.get('value')) for field in form_fields)
                    #login_values.append(login_form.find('input').get('value'))
                    #print(login_action)
                    #print(login_method)
                    #print(str(login_values))
                    #print(form_data)

                    #if ('username') in form_data: #Was initially used to only modify certain form parameters..now iterates through all keys/values in form_data dictionary
                    #    form_data['username'] = testload
                    #if ('user') in form_data:
                    #    form_data['user'] = testload
                    #if ('name') in form_data:
                    #    form_data['name'] = testload
                    #if ('userid') in form_data:
                    #    form_data['userid'] = testload
                    #if ('id') in form_data:
                    #    form_data['id'] = testload
                    #if ('query') in form_data:
                    #    form_data['query'] = testload
                    #if ('search') in form_data:
                    #    form_data['search'] = testload
                    #if ('password') in form_data:
                    #    form_data['password'] = testload
                    #if ('pass') in form_data:
                    #    form_data['pass'] = testload
                    #if ('data') in form_data:
                    #    form_data['data'] = testload
                    #if ('textfile') in form_data:
                    #    form_data['textfile'] = testload
                    #if ('file') in form_data:
                    #    form_data['file'] = testload
                    #if ('filename') in form_data:
                    #    form_data['filename'] = testload

                    #print(form_data)
                    #form_data_modded = {}
                    #form_data_modded = form_data.copy()
                    for key, value in form_data.items():
                        form_data_modded = {}
                        form_data_modded = form_data.copy()
                        #print(form_data)
                        form_data_modded[key] = testload
                        #print(form_data_modded)
                        if (("get") in login_method) or (("GET") in login_method):
                            #print("Submit via GET")
                            get_request = requests.get(host_base, params=form_data_modded, verify=False)
                            #get_request = http.request(login_action, host, fields=form_data)
                            print(get_request.url)
                            get_data = get_request.text

                            #print(get_data)a

                            parse_get = bs4.BeautifulSoup(get_data, 'html5lib')
                            #print(parse_get)
                            if ("alert(\"KOALA\")" or r"alert(\"KOALA\")") in str(parse_get):
                                print("XSS (REFLECTED) POTENTIAL VIA "+key+" : "+testload)
                                potential_xss.append(str(get_request.url))
                            else:
                                print("No Reflected XSS Detected using "+key+" : "+testload)
                                pass


                        elif (("post") in login_method) or (("POST") in login_method):
                            #print("Submit via POST")
                            post_request = requests.post(host, data=form_data_modded, verify=False)
                            print(post_request.url)
                            print("POST DATA :"+str(form_data))
                            post_data = post_request.text
                            parse_post = bs4.BeautifulSoup(post_data, 'html5lib')
                            #print(parse_post)
                            if ("alert(\"KOALA\")" or "alert(\\\"KOALA\\\")") in str(parse_post):
                                print("XSS (REFLECTED) POTENTIAL VIA "+key+" : "+testload)
                                potential_xss.append(str(post_request.url))
                            else:
                                print("No Reflected XSS Detected using "+key+" : "+testload)
                                pass
                        else:
                            print("Submit Method Not Detected!")

                else:
                    print("No username field found in current form")
                print("\n")


def sql_test(host): #Only error-based, need to add support for BLIND
    global potential_sql
    response_data = requests.get(host, verify=False)
    response_text = response_data.text
    potential_sql = []
    sql_tests = []
    #formsearch = 0
    file = open("sql.txt")
    sql_tests_pre = file.readlines()
    for test in sql_tests_pre:
        test = test.strip()
        sql_tests.append(test)
    total_params = []
    try:#If passed a PHP file, strips base URI from Data and tries to find all parameters
        host_base, host_ext = host.split('?')
        host_base = host_base + "?"
    except:
        host_base = host
    try:
        print("TEST")
        param_count = len(re.findall("&", host_ext))
        if param_count != 0:
            total_params = re.split("&", host_ext)
        else:
            total_params.append(host_ext)
        print(str(total_params))
    except:
        print("No GET parameters detected in URL!  Attempting to form-search..")
        #formsearch = 1
        host_base = host

    print(host_base)
    parse = bs4.BeautifulSoup(response_text, 'html.parser')
    all_forms = parse.find_all('form')

    if (args.Post) is not None:
        post_params = []
        for param in args.Post:
            post_params.append(param)
    if (args.Get) is not None:
        get_params = []
        for param in args.Get:
            get_params.append(param)


    print("\n")
    print("Initaiting SQL Injection Tests...")
    char_list = ['\'', ';', ' ', ')', ',', '\')', '), (', '-- -', '-- ', '-', ' -', '#', '\' ', '({ ', '/* ']
    error_list = [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"MySQL Error", r"Error executing query", "SQL syntax"] #Only supports MYSQL errors
    print("Utilzing following prefix/suffix list : "+str(char_list))
    print("Utilzing following base SQL Query list : "+str(sql_tests))
    len_char_list = len(char_list)
    #print(len_prefix_list)

    if args.formsearch == False:
        for i in range(len_char_list):
            suffix = char_list[i]

            for i in range(len_char_list):
                prefix = char_list[i]
            
                for i in range(len(sql_tests)):
                    payload_base = sql_tests[i]
                    payload_full = prefix+payload_base+suffix
                    base_index = 0
                    for i in range(len(total_params)):
                        param_base = ""
                        param_full = ""
                        param_length = ""
                        param_base = total_params[i].split("=")[0]
                        param_base = str(param_base)
                        param_base = param_base+"="
                        param_full = param_base + payload_full
                        #print(param_full)
                        if len(total_params) > 0:
                            print("\n")
                            print("Testing Parameter : "+param_base)
                            param_length = len(param_base)
                            index1 = host_ext.find(param_base)
                            index2 = host_ext.find('&', index1)
                            print("Length of Base Parameter : "+str(param_length))
                            print("Indexes to split on original Host string :"+str(index1)+" "+str(index2))
                            #print("Original String : "+host_ext)
                            altered_host_ext = host_ext[:index1+param_length]+payload_full+host_ext[index2:]
                            #print(altered_host_ext)
                            altered_request = host_base+altered_host_ext
                            print("PAYLOAD : "+payload_full)
                            print(altered_request)
                            get_request_test = requests.get(altered_request, verify=False)
                            get_request_data = get_request_test.text
                            for error in error_list:
                                if error in get_request_data:
                                    print("POTENTIAL MySQL ERROR-BASED INJECTION VIA DETECTION OF "+error)
                                    potential_sql.append(param_full)
                                    break
                        else:
                            altered_request = host_base+param_full
                            get_request_test = requests.get_data(altered_request)

    print("Starting Form Parsing...")

    if args.formsearch == True:  ##Not done
        for form in all_forms:
            form_action = form.get('action')
            form_method = form.get('method')
            form_fields = form.findAll('input')
            form_fields = form_fields + form.findAll('select')
            form_data_original = dict( (field.get('name'), field.get('value')) for field in form_fields)

            #print(form_data)
            if (("get") in form_method) or (("GET") in form_method):
                get_request = requests.get(host_base, params=form_data_original, verify=False)
                get_data_clean = get_request.text
            elif (("post") in form_method) or (("POST") in form_method):
                post_request = requests.post(host, data=form_data_original, verify=False)
                post_data_clean = post_request.text
            else:
                print("Submit Method Not Detected!")
                pass

            for i in range(len_char_list):
                suffix = char_list[i]

                for i in range(len_char_list):
                    prefix = char_list[i]
            
                    for i in range(len(sql_tests)):
                        payload_base = sql_tests[i]
                        payload_full = prefix+payload_base+suffix
                        base_index = 0
                        form_data = {}
                        form_data = form_data_original.copy() #build copy of original to reset on each loop to only test one parameter at a time

                        for key, value in form_data.items():
                            print("\n")
                            form_data = {}
                            form_data = form_data_original.copy()
                            if key != "page":
                                form_data[key] = payload_full
                            #print(form_data_original) #Finally works...stupid dictionaries.
                            #print(form_data)
                            if (("get") in form_method) or (("GET") in form_method):
                                get_request = requests.get(host_base, params=form_data, verify=False)
                                print("PAYLOAD : "+payload_full)
                                print(get_request.url)
                                get_data = get_request.text
                                for error in error_list:
                                    if error in get_data:
                                        print("POTENTIAL MySQL ERROR-BASED INJECTION VIA DETECTION OF '"+error+"' Using following key:value combination : "+str(key)+":"+payload_full)
                                        #print(str(key)+":"+payload_full)
                                        potential_sql.append(str(get_request.url))
                                        #potential_sql.append(str(key)+":"+payload_full)
                                        break


                            elif (("post") in form_method) or (("POST") in form_method):
                                post_request = requests.post(host, data=form_data, verify=False)
                                print("PAYLOAD : "+payload_full)
                                print(post_request.url)
                                print("POST DATA :"+str(form_data))
                                post_data = post_request.text
                                for error in error_list:
                                    if error in post_data:
                                        print("POTENTIAL MySQL ERROR-BASED INJECTION VIA DETECTION OF '"+error+"' Using following key:value combination : "+str(key)+":"+payload_full)
                                        #print(str(key)+":"+payload_full)
                                        potential_sql.append(str(post_request.url))
                                        #potential_sql.append(str(key)+":"+payload_full)
                                        break

def lfi_test(host): #Dynamic combination of dots+slashes to check for local file inclusion
    global lfi_win
    response_data = requests.get(host)
    response_text = response_data.text
    suffix_special = ['%00', '?', ' ', ';index.html', '%00index.html'] #Not yet Used
    prefix_special = [r'///', '\\\.'] #Not yet used
    dot_list = []
    slash_list = []
    lfi_win = []
    file1 = open('lfidot.txt')
    pre_dot_list = file1.readlines()
    file2 = open('lfislash.txt')
    pre_slash_list = file2.readlines()
    for i in range(len(pre_dot_list)):
        dot_list.append(pre_dot_list[i].strip())
    for i in range(len(pre_slash_list)):
        slash_list.append(pre_slash_list[i].strip())
    print("Dot List = "+str(dot_list))
    print("Slash List = "+str(slash_list))

    len_dot = len(dot_list)
    len_slash = len(slash_list)
    goal = r"etc/passwd"
    print("End Goal File : "+goal+"\n")
    succeed = 0

    for dot in dot_list:
        if succeed == 1:
            break
        for slash in slash_list:
            if succeed == 1:
                break
            for i in range(1, 5):
                if succeed == 1:
                    break
                if i == 1:
                    payload = dot+slash+goal
                if i == 2:
                    payload = dot+slash+dot+slash+goal
                if i == 3:
                    payload = dot+slash+dot+slash+dot+slash+goal
                if i == 4:
                    payload = dot+slash+dot+slash+dot+slash+dot+slash+goal
                if i == 5:
                    payload = dot+slash+dot+slash+dot+slash+dot+slash+dot+slash+goal
                check = requests.get(host+payload, verify=False)
                print(check.url)
                if ("root:") in check.text:
                    succeed = 1
                    win_payload = payload
                    print("'root:' detected in HTML response indicating Local File Inclusion Success!")
                    lfi_win.append(win_payload)
                    break
                else:
                    print("LFI Failure"+"\n")
                time.sleep(.1)
    print("LFI Payload Resulting in 'root:' inclusion : "+win_payload)


def crawl(host):
    global link_list
    link_list = []
    base_domain = "{0.scheme}://{0.netloc}{0.path}".format(urllib.parse.urlsplit(host))
    print("Limiting Crawling to Links Contained within : "+base_domain)
    response_data = requests.get(host)
    response_text = response_data.text
    soup_init = bs4.BeautifulSoup(response_text, 'html.parser')
    depth = int(args.depth[0])
    for link in soup_init.find_all('a'):
        new_link = urllib.parse.urljoin(base_domain, link.get('href'))
        if (base_domain in new_link) and (new_link not in link_list):
            link_list.append(new_link)
            print(new_link)
            if depth > 1:
                link_response_data = requests.get(new_link)
                link_response_text = link_response_data.text
                soup_depth2 = bs4.BeautifulSoup(link_response_text, 'html.parser')
                for link in soup_depth2.find_all('a'):
                    new_link = urllib.parse.urljoin(base_domain, link.get('href'))
                    if (base_domain in new_link) and (new_link not in link_list):
                        link_list.append(new_link)
                        print(new_link)
                        if depth > 2:
                            link_response_data = requests.get(new_link)
                            link_response_text = link_response_data.text
                            soup_depth3 = bs4.BeautifulSoup(link_response_text, 'html.parser')
                            for link in soup_depth3.find_all('a'):
                                new_link = urllib.parse.urljoin(base_domain, link.get('href'))
                                if (base_domain in new_link) and (new_link not in link_list):
                                    link_list.append(new_link)
                                    print(new_link)
                                    if depth > 3:
                                        link_response_data = requests.get(new_link)
                                        link_response_text = link_response_data.text
                                        soup_depth4 = bs4.BeautifulSoup(link_response_text, 'html.parser')
                                        for link in soup_depth4.find_all('a'):
                                            new_link = urllib.parse.urljoin(base_domain, link.get('href'))
                                            if (base_domain in new_link) and (new_link not in link_list):
                                                link_list.append(new_link)
                                                print(new_link)
                                                if depth > 4:
                                                    link_response_data = requests.get(new_link)
                                                    link_response_text = link_response_data.text
                                                    soup_depth5 = bs4.BeautifulSoup(link_response_text, 'html.parser')
                                                    for link in soup_depth5.find_all('a'):
                                                        new_link = urllib.parse.urljoin(base_domain, link.get('href'))
                                                        if (base_domain in new_link) and (new_link not in link_list):
                                                            link_list.append(new_link)
                                                            print(new_link)

main()
