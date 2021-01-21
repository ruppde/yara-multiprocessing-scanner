# yara multiprocessing scanner

* Example implementation of a fast recursive file scanner with multiprocessing using yara-python
* Speed reaches 50-75% of yara.c
* Works on linux, windows and mac os (uses start method "spawn")
* Runs with python 3 and 2
* Command line parameters aim to be compatible with yara.c (as far as implemented ;)
By arnim rupp

Speed:
- This script is ~25% slower than yara.c with 20 rules
- It's 100% slower than yara.c with 1600 rules (strange because I would assume that a bigger percentage of the work is done in the native C part. reason could be that every worker
  process needs it's own copy of the compiled rules in memory because they can't be shared (pickling doesn't work on C objects)

Things that could make this code faster:
- Find a way to have the compiled rules in some kind of shared memory to have more CPU cache hits. At the moment each worker process has its own compiled rules.

TODO:
[ ] Handle ctrl-c better

## Install

The only module, that needs to be installed, is yara-python. Use either pip to install yara-python or on debian "apt install python3-yara".

## Usage

```
usage: yara_multiprocessing_scanner.py [-h] [-r] [-p [THREADS]] RULES_FILE DIR

yara_multiprocessing_scanner.py, the pattern matching swiss army knife in python

positional arguments:
  RULES_FILE            Path to rules file
  DIR                   Path to scan

options:
  -h, --help            show this help message and exit
  -r, --recursive       recursively search directories
  -p [THREADS], --threads [THREADS]
                        use the specified NUMBER of threads to scan a directory (default is number of virtual cores)
```

## Licenses

Multilicensed under any of:
* GPL-2.0-or-later 
* AGPL-3.0-or-later
* CC-BY-4.0 


