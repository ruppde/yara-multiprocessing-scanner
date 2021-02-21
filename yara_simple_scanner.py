#!/usr/bin/env python3

'''
yara_simple_scanner.py

- Example implementation of a recursive file scanner using yara-python 
- Runs with python 3 and 2
- Command line parameters aim to be compatible with yara.c (as far as implemented ;)
- By arnim rupp 

Multi licensed:
GNU General Public License v3.0
AGPL 3.0 or later
Creative Commons 4.0 BY

'''

import yara      # pip install yara-python
import argparse
import plyara
import plyara.utils
from os import walk, path
from time import time


def yara_match(data):
    #print("yara_match: ", data)
    global count
    count += 1
    return yara.CALLBACK_CONTINUE

def do_scan(dirpath, rules, name):

    start = time()
    #print("scaning: ", path)
    global count
    count = 0
    for root, directories, files in walk(dirpath, followlinks=False):

        for filename in files:
            #print(root, filename)
            filePath = path.join(root, filename)
            #print("scanning " , filePath)
            try:
                matches = rules.match(filePath, 
                        fast=True,
                        # callback makes no difference
                        #which_callbacks=yara.CALLBACK_MATCHES,
                        #callback=yara_match,
                        )
                if matches:
                    for match in matches:
                        #print(match.rule, filePath)
                        count += 1
            except Exception as e:
                print("ERROR", "FileScan", "Cannot YARA scan file: %s" % filePath)

                if not args.recursive:
                    break

    end = time()
    print("scan took: %0.2f - matches: %d with \"%s\" " % ( ( end - start ), count, name ))



############################### main() ###########################################

def main():

    # Argument parsing
    parser = argparse.ArgumentParser(description='yara_simple_scanner.py')
    parser.add_argument('RULES_FILE', help='Path to rules file')
    parser.add_argument('DIR', help='Path to scan')
    parser.add_argument('-r','--recursive',  help='recursively search directories',  action="store_true")
    parser.add_argument('-p',  help='Ignored, just here for lazyness purposes to have compatible params', action="store_true")

    args = parser.parse_args()

    rulesfile = args.RULES_FILE
    
    print("Loading original rules from %s" % (rulesfile))
    rules = yara.compile(filepaths={
      'rules':rulesfile
    })

    print("Creating copy of rules with stripped metadata")
    parser = plyara.Plyara()
    with open(rulesfile, 'r') as fh:
        yararules = parser.parse_string(fh.read())
    stripped_rules_plain = []
    for rule in yararules:
        rule['metadata'] = ""
        stripped_rules_plain.append(plyara.utils.rebuild_yara_rule(rule) )

    rules_stripped = yara.compile(source=''.join(stripped_rules_plain))
    print("Finished loading rules")


    dirpath = str(args.DIR)
    print("Scaning starts\n")
    do_scan(dirpath, rules_stripped, "rules stripped_meta")
    do_scan(dirpath, rules, "rules original")
    print("\nOne more round to rule out caching effects:")
    do_scan(dirpath, rules_stripped, "rules stripped_meta")
    do_scan(dirpath, rules, "rules original")

if __name__ == '__main__':
    main()

