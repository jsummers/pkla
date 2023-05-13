# pkla.py

By Jason Summers.

Terms of use: MIT license. See COPYING.txt.

pkla.py ("pkla") is a Python script that analyzes a PKLITE-compressed DOS
EXE file, and prints the compression parameters. It can also "descramble"
a certain obfuscated part fo the file, if present.

It is experimental. I'm using this script as a test-bed, to try to figure
out a good way to do this.

Its main strategy is to test for signature byte patterns in known
locations, follow "jumps" and similar instructions, and walk through the
file, using extensive knowledge of the different versions of the format.
Sometimes it resorts to scanning a part of the file for particular byte
patterns, if there are too many format variants to enumerate.

TODO:
* Documentation.
* Support COM format. Easy, but low priority.
* Better names for some of the segment "classes".
* Better support for beta-version files.
* Detect the version of PKLITE (or ZIP2EXE) that made the file.

Not planned:
* Decompression, or any feature that would require it.
* Support for PKLITE[32]-compressed Windows executables.
