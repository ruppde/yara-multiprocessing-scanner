# yara multiprocessing scanner

This is an example implementation of a fast recursive file scanner with multiprocessing using yara-python. It has no advantage over the command line scanner of the official yara package (yara.c) and less features. But if you want to implement your own features, it might be a good starting point as it's not so trivial to combine yara-python with multiprocessing. The objects with C-bindings can't be pickled, so you need to compile the rules in each worker thread. That would be slow, if it would happen before each single scan. Also you don't want to wait with the first scan until the directory walk is complete. So the workers are started, compile the rules and get their workload form a queue.

Features:
* Speed reaches 50-75% of yara.c
* Works on Linux, Windows and Mac OS (uses start method "spawn")
* Runs with Python 3 and 2
* Command line parameters aim to be compatible with yara.c (as far as implemented ;)
* It does not follow symlinks so it resembles "yara -N" (symlink handling isn't proper in yara.c anyway, try to scan /usr/bin on debian. It contains the symlink "X11 -> ." which yara.c follows indefinitely.)


Speed:
- This script reaches 75% of the speed of yara.c with 20 rules.
- It reaches 50% of the speed of yara.c with 1600 rules (strange because I would assume that a bigger percentage of the work is done in the native C part. Reason could be that every worker process needs it's own copy of the compiled rules in memory because they can't be shared. (pickling doesn't work on C objects.)

Things that could make this code faster:
- Find a way to have the compiled rules in some kind of shared memory to have more CPU cache hits. At the moment each worker process has its own compiled rules.

Todo:
- [ ] Handle ctrl-c better

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

# YARA simple scanner

Features:
- Example implementation of a recursive file scanner using yara-python
- Runs with python 3 and 2
- Command line parameters aim to be compatible with yara.c (as far as implemented ;)


## Usage
```
$ ./yara_simple_scanner.py -h
usage: yara_simple_scanner.py [-h] [-r] [-p [P]] RULES_FILE DIR

yara_simple_scanner.py

positional arguments:
  RULES_FILE       Path to rules file
  DIR              Path to scan

optional arguments:
  -h, --help       show this help message and exit
  -r, --recursive  recursively search directories
  -p               Ignored, just here for lazyness purposes to have compatible params
```


## License

Multi licensed under:
* GNU General Public License v2.0 or later
* AGPL 3.0 or later
* Create Commons 4.0 BY

## Author

Arnim Rupp
