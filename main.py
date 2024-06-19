"""
Main file for detecting webshells in a path or file
"""
from datetime import datetime
import argparse
import hashlib
import os
import sys
import shutil
import yara

def check_requirements():
    """for checking the running OS and permission of the user"""
    if os.name != 'posix':
        print('This script is only compatible with Unix-based systems')
        sys.exit(1)

    if os.getuid() != 0:
        print("You must be root to run this script")
        sys.exit(1)

def  start_scan(path, directory = False):
    """for scanning files using yara rules"""
    if not os.path.exists(basepath + '/signatures/core.yar'):
        print("The signature file is missing. Unable to start scan.")
        return
    rules = yara.compile(basepath + '/signatures/core.yar')

    if directory:
        for root, dir, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                print(f'Scanned {file_path}')
                try:
                    matches = rules.match(file_path)
                    if matches:
                        if mode == 'quarantine':
                            shutil.move(file_path, basepath + '/.detection')
                        elif mode == 'remove':
                            os.remove(file_path)
                        print(f'Rule matched in file {file_path}:')
                        for match in matches:
                            print(f'    - {match.rule}')
                except yara.Error as e:
                    print(f'Error scanning file {file_path}: {e}')
    else:
        try:
            matches = rules.match(path)
            if matches:
                if mode == 'quarantine':
                    shutil.move(path, basepath + '/.detection')
                elif mode == 'remove':
                    os.remove(path)
                print(f'Rule matched in file {path}:')
                for match in matches:
                    print(f'    - {match.rule}')
        except yara.Error as e:
            print(f'Error scanning file {path}: {e}')

def main():
    """main function for the script"""
    check_requirements()

    global basepath 
    basepath = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser()
    path = parser.add_mutually_exclusive_group(required=True)
    path.add_argument('-c', '--clear', help='Clear all quarantined files. This option must be used alone', action='store_true')
    path.add_argument('-p', '--path', type=str, help='Path to the directory to scan')
    path.add_argument('-f', '--file', type=str, help='File to scan')
    scanmode = parser.add_mutually_exclusive_group()
    scanmode.add_argument('-r', '--remove', help='Enable positive artifact removal', action='store_true')
    scanmode.add_argument('-q', '--quarantine', help='Enable positive artifact quarantine. Quarantined files are stored in ./.detection', action='store_true')
    param = parser.parse_args()

    path = param.path
    file = param.file
    clear = param.clear
    if clear:
        print(f'Wiping quarantined files in {basepath}/.detection')
        shutil.rmtree(basepath + '/.detection/', ignore_errors=True)
        print('Successfully wiped quarantined files')
        sys.exit()
    
    global mode
    if param.quarantine:
        mode = 'quarantine'
    elif param.remove:
        mode = 'remove'
    else:  
        mode = 'scan'

    os.makedirs(basepath + '/.detection', exist_ok=True)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print("=============================================")
    print(f'Scan initated at {timestamp}, running in {mode} mode')

    if path and os.path.isdir(path):
        start_scan(path,  True)
    elif file and  os.path.isfile(file):
        start_scan(file)
    else:
        print('Invalid path or file supplied')
    
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(f'Scan finished at {timestamp}.')
    print("=================End of Scan==================")

if __name__ == "__main__":
    main()