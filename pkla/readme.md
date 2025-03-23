# pkla.py

By Jason Summers.

Terms of use: MIT license. See COPYING.txt.

pkla.py ("pkla") is a Python script that analyzes a PKLITE-compressed DOS
EXE or COM file, and prints the compression parameters.

It is experimental. I'm using this script as a test-bed, to try to figure
out a good way to do this.

Its main strategy is to test for signature byte patterns in known
locations, follow "jumps" and similar instructions, and walk through the
file, using extensive knowledge of the different versions of the format.
Sometimes it resorts to scanning a part of the file for particular byte
patterns, if there are too many format variants to enumerate.

-----

The "-p" option causes each output item to be tagged with an indication
of its importance with respect to decompressing the file. The following
tags are used:

* "CRIT" - Needed to decompress the main part of the program.
* "HIGH" - Needed to decompress to a runnable file.
* "MED" - Useful for best results.
* "LOW" - Might have *some* use.
* "INFO" - Not needed.

The tags reflect the importance of that item in general, not necessarily
the importance in the particular file being analyzed.

-----

The "-s" option creates a modified version of the input file, with a
certain "scrambled" section of it descrambled. This makes the file
easier to analyze. This applies mainly to files created with the
Professional version of PKLITE v1.14 and higher.

-----

Pkla does not support decompression, and I never anticipated that it
would do so.

Unfortunately, as far as I know, it is not possible to find the
compressed relocation table, or in some cases the "footer" segment that
follows it, without decompressing the compressed data (or at least going
through the motions of it). It would certainly be nice if Pkla could
report the locations of these items. So I'm not taking it off the table.
Some form of decompression ability might be added to a future version,
though it's not currently planned.
