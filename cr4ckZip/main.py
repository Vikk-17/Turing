#!/usr/bin/python3

import sys
import argparse, textwrap
import zipfile
from pwn import *

def main():
    parser = argparse.ArgumentParser(
            description="Zip file password Cracking Script by hipst3r0x", 
            formatter_class=argparse.RawTextHelpFormatter, 
            epilog=textwrap.dedent(
                '''
                Script Usage:
                ./cr4cker.py -z secrets.zip -w wordlist.txt -d myfolder
                ./cr4cker.py -z secrets.zip -w wordlist.txt -d ~/Documents/myfolder
                '''
            )
    )
    
    parser.add_argument("-z", "--zip", help="Encrypted Zip file")
    parser.add_argument("-w", "--wordlist", help="Password Dictionary")
    parser.add_argument("-d", "--directory", help="Destination Folder to extract content")
    args = parser.parse_args()
    
    """
    Checking the args in terminal
    """
    if len(sys.argv) < 2:
        log.failure(f"Script Usage: ./cr4cker.py -h [help] -z [secrets.zip] -w [wordlists.txt] -d [directory]")
        sys.exit(1)

    # Fetching the data from argparse
    zip = zipfile.ZipFile(args.zip)
    wordlist = args.wordlist
    directory = args.directory

    # Print the banner
    banner = log.info(f"Zip file Password Cracking")
    print()
    stats = log.progress(f"Breaking")
    time.sleep(2)
    print()

    words = open(wordlist, "rb")
    for password in words:
        password = password.strip()
        stats.status(f"Trying with password {password.decode(errors='ignore')}")
        try:
            zip.extractall(path=f"{directory}", pwd=password)
        except:
            continue
        else:
            log.success("Success!!")
            log.success(f"Password found: {password.decode()}")
            log.success(f"Files Extracted inside -> {directory} directory!")
            sys.exit(0)
    log.failure(f"Password not found, don't you have another wordlist?")


if __name__ == "__main__":
    main()
