# ncmlib
Copyright (C) 2010-2017 Nicholas J. Kain.  Licensed under 2-clause BSD.

This library is used by many of my programs.  It is statically linked, and
should be extracted to a ncmlib subdirectory in the program source directory
before building.

| Filename     |  Purpose                                        | 
| ------------ | ----------------------------------------------- |
| exec         |  Creation of subprocesses                       |
| hwrng        |  Abstraction API for getrandom() or /dev/random |
| io           |  Wrappers for low-level i/o functions           |
| log          |  Logging to stdio or syslog                     |
| malloc       |  Allocate-or-die wrappers                       |
| net_checksum |  IP checksum functions                          |
| pidfile      |  Pidfile creation                               |
| privilege    |  Drop uid/gid/capabilities securely             |
| random       |  Tyche-based PRNG                               |
| signals      |  Wrappers for signal hooks                      |

