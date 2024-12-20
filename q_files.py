#!/usr/bin/python3
import sys
import getopt
import getpass
import requests
import json
import time
import urllib.parse
import urllib3
urllib3.disable_warnings()
import os
import re
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    sys.stderr.write("Usage: q_files.py [-HD] [-t token] [-c creds] [-f token_file] command qumulo [file file ...]\n")
    sys.stderr.write("-h | --help : Displays the Usage\n")
    sys.stderr.write("-D | --DEBUG : Provides debug information\n")
    sys.stderr.write("-F | --files-only : Only show files, not directories\n")
    sys.stderr.write('-c | --creds : Login credentials format user:password\n')
    sys.stderr.write('-t | --token : Use an auth token\n')
    sys.stderr.write('-f | --token-file : Use a token file generated from qq auth_create_token\n')
    sys.stderr.write("command : list and close are currently supported\n")
    sys.stderr.write("qumulo : Name or IP address of a Qumulo node\n")
    sys.stderr.write("file file ... : A list of file names, ids, or locations. Space separated.\n")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def api_login(qumulo, user, password, token):
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input("User: ")
        if not password:
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    dprint("AUTH_HEADERS: " + str(auth_headers))
    return(auth_headers)

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def qumulo_post(addr, api, body):
    dprint("API_POST: " + api + " : " + str(body))
    good = False
    while not good:
        good = True
        try:
            res = requests.post('https://' + addr + '/api' + api, headers=auth, data=body, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying....")
            time.sleep(5)
            good = False
    results = json.loads(res.content.decode('utf-8'))
    if res.status_code == 200:
        return (results)
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + '\n')
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

def get_open_files (qumulo, FILES_ONLY):
    files_list = []
    open_files = qumulo_get(qumulo, '/v1/smb/files/?resolve_paths=true')
    for f in open_files['file_handles']:
        if f['handle_info']['path'].endswith('/') and FILES_ONLY:
            continue
        id = f['file_number']
        name = f['handle_info']['path']
        location = f['handle_info']['location']
        files_list.append({'name': name, 'id': id, 'location': location})
    return(files_list)

def get_fh(files, f):
    fh_list = []
    found = False
    for fc in files:
        if f.startswith('/') and fc['name'] == f:
            body = {'file_number': 0, 'handle_info': {'owner': '0', 'access_mask': ['MS_ACCESS_FILE_READ_ATTRIBUTES'],
                                                      'version': 0, 'location': fc['location'], 'num_byte_range_locks': 0}}
            found = True
            fh_list.append(body)
        elif fc['id'] == f:
            body = {'file_number': 0, 'handle_info': {'owner': '0', 'access_mask': ['MS_ACCESS_FILE_READ_ATTRIBUTES'],
                                                      'version': 0, 'location': fc['location'], 'num_byte_range_locks': 0}}
            found = True
            fh_list.append(body)
    if not found:
        sys.stderr.write('Unrecognized file [get_fh]: ' + f + '\n')
        exit(2)
    return(fh_list)

if __name__ == "__main__":
    DEBUG = False
    VERBOSE = False
    FILES_ONLY = False
    token = ""
    token_file = ""
    default_token_file = ".qfsd_cred"
    user = ""
    password = ""
    headers = {}
    timeout = 360
    cmd = ""
    supported_cmds = ['list', 'close']
    files = []
    files_to_close = []
    locations = []
    filters = []

    optlist, args = getopt.getopt(sys.argv[1:], 'hDFt:c:f:', ['help', 'DEBUG', 'files-only', 'token=', 'creds=',
                                                            'token-file='])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-F', '--files-only'):
            FILES_ONLY = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-f', '--token-file'):
            token = get_token_from_file(a)
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')

    cmd = args.pop(0).lower()
    if cmd not in supported_cmds:
        sys.stderr.write("Invalid Command: " + cmd + "  Supported Commands: " + str(supported_cmds) + '\n')
        exit(1)
    qumulo = args.pop(0)
    if not user and not token:
        if not token_file:
            token_file = default_token_file
        if os.path.isfile(token_file):
            token = get_token_from_file(token_file)
    auth = api_login(qumulo, user, password, token)
    dprint(str(auth))
    if cmd == "list":
        filters = args
        dprint("FILERS: " + str(filters))
        table = [['id:', 'location:', 'path:'], ['===', '=========', '=====']]
        files = get_open_files(qumulo, FILES_ONLY)
        for f in files:
            match = True
            if filters and f['name']:
                match = False
                for pattern in filters:
                    if re.search(pattern, f['name']):
                        match = True
                        break
            if match:
                table.append([f['id'], f['location'], f['name']])
        widths = [max(map(len, col)) for col in zip(*table)]
        for row in table:
            print("  ".join((val.ljust(width) for val, width in zip(row, widths))))
    elif cmd == "close":
        files_to_close = args
        files = get_open_files(qumulo, FILES_ONLY)
        for f in files_to_close:
            if '.' in f and not f.startswith('/'):
                body = {'file_number': 0, 'handle_info': {'owner': '0', 'access_mask': ['MS_ACCESS_FILE_READ_ATTRIBUTES'],
                                                          'version': 0, 'location': f, 'num_byte_range_locks': 0}}
                locations.append(body)
            elif f.isdigit() or f.startswith('/'):
                locations = get_fh(files, f)
            else:
                sys.stderr.write("Unrecognized file [main]: " + f)
                exit(2)
        dprint(str(locations))
        res = qumulo_post(qumulo, '/v1/smb/files/close', json.dumps(locations))
