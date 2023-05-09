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

Another strategy would be to rely heavily on scanning for byte patterns in
not-precisely-known locations. This has pros and cons. The current version
of pkla deliberately tries to avoid this, though it may still do some
scanning in a few places.

TODO:
* Detection of "extra" compression (for all files).
* Documentation.
* Support certain "protectors", like UN2PACK and MEGALITE.
* Support COM format. Easy, but low priority.
* Better names for some of the segment "classes".
* Better support for beta-version files.

Not planned:
* Decompression, or any feature that would require it.
* Support for PKLITE[32]-compressed Windows executables.
