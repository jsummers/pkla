#!/usr/bin/python3

# pkla.py
# Version 2023.05.10.00
# by Jason Summers
#
# A script to parse a PKLITE-compressed DOS EXE file, and
# print compression parameters.
#
# Terms of use: MIT license. See COPYING.txt.

import sys

class pkla_property:
    def __init__(self, dfltval):
        self.val_known = False
        self.val = dfltval
    def set(self, x):
        self.val = x
        self.val_known = True
    def get(self):
        return self.val
    def is_true(self):
        if self.val_known and self.val:
            return True
        else:
            return False
    def is_false(self):
        if self.val_known and (not self.val):
            return True
        else:
            return False
    def is_true_or_unk(self):
        if (not self.val_known) or self.val:
            return True
        else:
            return False
    def is_false_or_unk(self):
        if (not self.val_known) or (not self.val):
            return True
        else:
            return False
    def getvalpr(self):
        if self.val_known:
            return self.val
        else:
            return '?'
    def getvalpr_hex(self):
        if self.val_known:
            return '0x%04x' % (self.val)
        else:
            return '?'
    def getvalpr_hex1(self):
        if self.val_known:
            return '0x%02x' % (self.val)
        else:
            return '?'
    def getvalpr_yesno(self):
        if self.val_known:
            if self.val:
                return 'yes'
            else:
                return 'no'
        else:
            return '?'

class pkla_bool(pkla_property):
    def __init__(self):
        pkla_property.__init__(self, False)

class pkla_number(pkla_property):
    def __init__(self):
        pkla_property.__init__(self, 0)

class pkla_string(pkla_property):
    def __init__(self):
        pkla_property.__init__(self, '?')

class pkla_segment:
    def __init__(self):
        self.segclass = pkla_string()
        self.pos = pkla_number()

class context:
    def __init__(ctx):
        ctx.errmsg = ''

        ctx.file_size = pkla_number()
        ctx.ver_info = pkla_number()
        ctx.entrypoint = pkla_number()
        ctx.codestart = pkla_number()
        ctx.codeend = pkla_number()
        ctx.overlay_size = pkla_number()

        ctx.intro = pkla_segment()
        ctx.errorhandler = pkla_segment()
        ctx.position2 = pkla_number()  # Next part after intro: descrambler or copier pos
        ctx.descrambler = pkla_segment()
        ctx.copier = pkla_segment()
        ctx.copier_subclass = pkla_string()
        ctx.decompr = pkla_segment()

        ctx.approx_end_of_decompressor = pkla_number()
        ctx.start_of_cmpr_data = pkla_number()
        ctx.offsets_key = pkla_number()

        ctx.is_scrambled = pkla_bool()
        ctx.previously_descrambled = pkla_bool()
        ctx.initial_key = pkla_number()
        ctx.pos_of_scrambled_word_count = 0
        ctx.scrambled_word_count = 0
        ctx.pos_of_last_scrambled_word = 0
        ctx.scrambled_section_startpos = pkla_number()
        ctx.scramble_algorithm = pkla_number()

        ctx.is_beta = pkla_bool()
        ctx.large_compression = pkla_bool()
        ctx.extra_compression = pkla_bool()
        ctx.v120_compression = pkla_bool()
        ctx.obfuscated_offsets = pkla_bool()


def getbyte(ctx, offset):
    return ctx.blob[offset]

def getu16(ctx, offset):
    val = ctx.blob[offset] + 256*ctx.blob[offset+1]
    return val

def gets16(ctx, offset):
    val = getu16(ctx, offset)
    if val >= 0x8000:
        val -= 0x10000
    return val

def putu16(ctx, val, offset):
    ctx.blob[offset] = val % 256
    ctx.blob[offset+1] = val // 256

def follow_1byte_jmp(ctx, pos):
    return pos + 1 + ctx.blob[pos]

def ip_to_filepos(ctx, ip):
    return ctx.codestart.get() + (ip - 0x0100)

def byte_seq_matches(ctx, pos1, vals, wildcard):
    if pos1+len(vals) > len(ctx.blob):
        return False

    for i in range(len(vals)):
        if vals[i] == wildcard:
            continue
        if ctx.blob[pos1+i] != vals[i]:
            return False

    return True

def find_byte_seq_match(ctx, startpos, maxbytes, vals, wildcard):
    pos = startpos

    while pos < startpos+maxbytes:
        foundmatch = True

        for i in range(len(vals)):
            if vals[i] == wildcard:
                continue
            if ctx.blob[pos+i] != vals[i]:
                foundmatch = False
                break

        if foundmatch:
            return True, pos

        pos += 1

    return False, 0

def find_byte_seq(ctx, startpos, maxbytes, vals):
    pos = startpos

    while pos < startpos+maxbytes:

        foundmatch = True

        for i in range(len(vals)):
            if ctx.blob[pos+i] != vals[i]:
                foundmatch = False
                break

        if foundmatch:
            return True, pos

        pos += 1

    return False, 0

def pkl_open_file(ctx):
    inf = open(ctx.infilename, "rb")
    ctx.blob = bytearray(inf.read())
    inf.close()
    ctx.file_size.set(len(ctx.blob))

def pkl_read_exe(ctx):
    sig = getu16(ctx, 0)
    if sig!=0x5a4d and sig!=0x4d5a:
        ctx.errmsg = "Not an EXE file"
        return

    e_cblp = getu16(ctx, 2)
    e_cp = getu16(ctx, 4)

    e_cparhdr = getu16(ctx, 8)
    ctx.codestart.set(e_cparhdr*16)

    if e_cblp==0:
        ctx.codeend.set(512 * e_cp)
    else:
        ctx.codeend.set(512 * (e_cp-1) + e_cblp)

    ip = getu16(ctx, 20)
    cs = gets16(ctx, 22)
    ctx.entrypoint.set(ctx.codestart.get() + 16*cs + ip)

    if ctx.codeend.get() <= ctx.file_size.get():
        ctx.overlay_size.set(ctx.file_size.get() - ctx.codeend.get())
    else:
        ctx.errmsg = "Truncated EXE file"
        return

    ctx.ver_info.set(getu16(ctx, 28))

# Decode the first part of the executable code, and
# find "position2": the position of the descrambler, or, if not scrambled,
# the position of the copier. This is usually right after the
# "Not enough memory" message.
def pkl_decode_intro(ctx):
    pos = ctx.entrypoint.get()

    if byte_seq_matches(ctx, pos,
        b'\x2e\x8c\x1e??\x8b\x1e??\x8c\xda??????\x72', 0x3f):
        ctx.intro.segclass.set('beta')
        ctx.is_beta.set(True)
    elif byte_seq_matches(ctx, pos,
        b'\x2e\x8c\x1e??\xfc\x8c\xc8', 0x3f):
        ctx.intro.segclass.set("beta_lh")
        ctx.is_beta.set(True)
    elif byte_seq_matches(ctx, pos,
        b'\xb8??\xba??\x8c\xdb\x03\xd8\x3b\x1e\x02\x00\x73', 0x3f):
        ctx.intro.segclass.set("1.00")
        ctx.is_scrambled.set(False)
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+15))
        ctx.position2.set(pos+16)
    elif byte_seq_matches(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x73', 0x3f):
        ctx.intro.segclass.set("1.12")
        ctx.initial_key.set(getu16(ctx, pos+4))
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+14))
        ctx.position2.set(pos+15)
    elif byte_seq_matches(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72', 0x3f):
        ctx.intro.segclass.set("1.14")
        ctx.initial_key.set(getu16(ctx, pos+4))
        ctx.position2.set(follow_1byte_jmp(ctx, pos+14))
        ctx.errorhandler.pos.set(pos+15)
    elif byte_seq_matches(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x2d\x73\x67\x72', 0x3f):
        ctx.intro.segclass.set("megalite")
        ctx.initial_key.set(getu16(ctx, pos+4))
        ctx.position2.set(follow_1byte_jmp(ctx, pos+14))
        ctx.errorhandler.pos.set(pos+15)
    elif byte_seq_matches(ctx, pos,
        b'\x50\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72', 0x3f):
        ctx.intro.segclass.set("1.50")
        ctx.initial_key.set(getu16(ctx, pos+5))
        ctx.position2.set(follow_1byte_jmp(ctx, pos+15))
        ctx.errorhandler.pos.set(pos+16)
    elif byte_seq_matches(ctx, pos,
        b'\x9c\xba??\x2d??\x81\xe1??\x81\xf3??\xb4??'
        b'\xb8??\xba??\x8c', 0x3f):
        ctx.intro.segclass.set("un2pack")
        ctx.is_scrambled.set(False)
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+18+15))
        ctx.position2.set(pos+18+16)
    elif byte_seq_matches(ctx, pos,
        b'\x9c\xba??\x2d??\x81\xe1??\x81\xf3??\xb4', 0x3f):
        ctx.intro.segclass.set("un2pack_corrupt")

    if not ctx.intro.segclass.val_known:
        ctx.errmsg = 'Unknown PKLITE version, or not a PKLITE-compressed file'

    if ctx.intro.segclass.val_known:
        ctx.intro.pos.set(ctx.entrypoint.get())
        if not ctx.is_beta.val_known:
            ctx.is_beta.set(False)

# Decide if scrambling is used.
# If so, figure out the scrambling params.
def pkl_detect_and_decode_descrambler(ctx):

    if ctx.is_beta.is_true():
        ctx.is_scrambled.set(False)
        return

    if(not ctx.position2.val_known):
        return

    if ctx.is_scrambled.is_false():
        return

    scrambled_count_raw = 0
    pos_of_endpos_field = 0
    pos_of_jmp_field = 0
    pos = ctx.position2.get()

    if byte_seq_matches(ctx, pos,
        b'\x2d\x20\x00\x8e\xd0\x2d??\x50\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x90\x49\x74?\xad\x92\x33\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.14scrambled')
        ctx.scramble_algorithm.set(1) # 33 = XOR
        ctx.pos_of_scrambled_word_count = pos+11
        pos_of_endpos_field = pos+14
        pos_of_jmp_field = pos + 22
    elif byte_seq_matches(ctx, pos,
        b'\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.20var1') # e.g. pklite.exe 1.15
        ctx.scramble_algorithm.set(2)  # 03 = ADD
        ctx.pos_of_scrambled_word_count = pos+10
        pos_of_endpos_field = pos+13
        pos_of_jmp_field = pos + 20
    elif byte_seq_matches(ctx, pos,
        b'\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x90\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.20var1b') # e.g. pkzfind.exe
        ctx.scramble_algorithm.set(2)  # 03 = ADD
        ctx.pos_of_scrambled_word_count = pos+10
        pos_of_endpos_field = pos+13
        pos_of_jmp_field = pos + 21
    elif byte_seq_matches(ctx, pos,
        b'\x59\x2d\x20\x00\x8e\xd0\x51??\x00\x50\x80\x3e'
        b'\x41\x01\xc3\x75\xe6\x52\xb8??\xbe??\x56\x56\x52\x50\x90'
        b'???????\x74???????\x33', 0x3f):
        ctx.descrambler.segclass.set('1.50scrambled')
        ctx.scramble_algorithm.set(1)
        ctx.pos_of_scrambled_word_count = pos+20
        pos_of_endpos_field = pos+23
        pos_of_jmp_field = pos + 38
    elif byte_seq_matches(ctx, pos,
        b'\x2d\x20\x00????????????\xb9??\xbe????????\x74???\x03', 0x3f):
        ctx.descrambler.segclass.set('1.20var2') # e.g. pkzip.exe 2.04g
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+16
        pos_of_endpos_field = pos+19
        pos_of_jmp_field = pos+28
    elif byte_seq_matches(ctx, pos,
        b'\x2d\x20\x00????????????\xb9??\xbe?????????\x74???\x03', 0x3f):
        ctx.descrambler.segclass.set('1.20pkzip204clike')
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+16
        pos_of_endpos_field = pos+19
        pos_of_jmp_field = pos+29
    elif byte_seq_matches(ctx, pos,
        b'\x2d\x20\x00?????????????????\xb9??\xbe??????????\x74???\x03', 0x3f):
        # TODO: The fact that we need several special patterns just for the
        # PKLITE 2.01 distribution files is concerning.
        # But it's hard to generalize from so few files. And the polymorphic
        # code files from this era use in the descrambler doesn't help
        # matters.
        ctx.descrambler.segclass.set('pklite2.01like')
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+21
        pos_of_endpos_field = pos+24
        pos_of_jmp_field = pos+35
    elif byte_seq_matches(ctx, pos,
        b'\x8b\xfc\x81?????????????\xbb??\xbe??????\x74???\x03', 0x3f):
        ctx.descrambler.segclass.set('chk4lite2.01like')
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+17
        pos_of_endpos_field = pos+20
        pos_of_jmp_field = pos+27

    found_params = ctx.descrambler.segclass.val_known
    if found_params:
        ctx.is_scrambled.set(True)
        scrambled_count_raw = getu16(ctx, ctx.pos_of_scrambled_word_count)
        if scrambled_count_raw > 0:
            ctx.scrambled_word_count = scrambled_count_raw - 1
        if scrambled_count_raw==1:
            ctx.previously_descrambled.set(True)
        scrambled_endpos_raw = getu16(ctx, pos_of_endpos_field)
        ctx.pos_of_last_scrambled_word = ip_to_filepos(ctx, scrambled_endpos_raw)
        ctx.scrambled_section_startpos.set(follow_1byte_jmp(ctx, pos_of_jmp_field))

    if ctx.is_scrambled.is_true():
        ctx.descrambler.pos.set(pos)
    if ctx.scramble_algorithm.get()==2:
        ctx.v120_compression.set(True)
    elif ctx.scramble_algorithm.get()==1:
        ctx.v120_compression.set(False)

def pkl_descramble(ctx):
    if ctx.is_scrambled.is_false_or_unk():
        return
    if not ctx.scramble_algorithm.val_known:
        return
    if (not ctx.scrambled_section_startpos.val_known) or \
        ctx.pos_of_last_scrambled_word==0:
        return
    if ctx.pos_of_scrambled_word_count==0:
        return
    if ctx.scrambled_word_count < 1:
        return

    # The count is biased by 1. We set it to 1, meaning 0 scrambled words.
    putu16(ctx, 0x0001, ctx.pos_of_scrambled_word_count)

    if ctx.scramble_algorithm.get()==2:
        alg_ADD = True
    else:
        alg_ADD = False

    for i in range(ctx.pos_of_last_scrambled_word+2 - \
        (ctx.scrambled_word_count*2), \
        ctx.pos_of_last_scrambled_word+2, 2):
        n1 = getu16(ctx, i)
        if i==ctx.pos_of_last_scrambled_word:
            n2 = ctx.initial_key.get()
        else:
            n2 = getu16(ctx, i+2)

        if alg_ADD:
            val = (n1 + n2) % 65536
        else:
            val = n1 ^ n2
        putu16(ctx, val, i)

# What we call the 'copier' is the part of the code that starts at
# the beginning of the scrambled section, if there is a scrambled
# section.
# If there is no scrambled section, it's the part that executes right
# after a successful check for sufficient memory.
# The 'copier' always ends with a small block of code that copies the
# decompressor out of the way. Then it does some type of 'ret'
# instruction to "return" to an address that it recently pushed onto
# the stack. It's that pushed address that we want to find. We'll use
# it to reliably find the start of the decompressor in the file.
def pkl_decode_copier(ctx):
    if ctx.copier.pos.val_known:
        pos = ctx.copier.pos.get()
    elif ctx.is_scrambled.is_true():
        pos = ctx.scrambled_section_startpos.get()
    else:
        pos = ctx.position2.get()

    pos_of_decompr_pos_field = 0
    amt_to_scan = 60
    found = False

    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('common')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5\xca', 0x3f)
        if found:
            ctx.copier.segclass.set('1.50scrambled')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xfc\xbe??\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('pklite2.01like')
            pos_of_decompr_pos_field = foundpos+8
    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\x57\xb9??\xbe??\xfc\xf3\xa5\xc3', 0x3f)
        if found:
            ctx.copier.segclass.set('1.20var1small')
            pos_of_decompr_pos_field = foundpos+5
    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x56\xbe??\xfc\xf2\xa5\xca', 0x3f)
        if found:
            ctx.copier.segclass.set('megalite')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_byte_seq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x2b\xff\x57\xbe??\xfc\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('un2pack')
            pos_of_decompr_pos_field = foundpos+7

    if found:
        ctx.copier_subclass.set('%s+%d' % (ctx.copier.segclass.get(), \
            pos_of_decompr_pos_field-pos))
        ctx.copier.pos.set(pos)
        ctx.decompr.pos.set(ip_to_filepos(ctx, getu16(ctx, pos_of_decompr_pos_field)))
        if ctx.copier.pos.get()==ctx.position2.get():
            # We found the copier at 'position2', so
            # there's definitely no scrambled section.
            ctx.is_scrambled.set(False)

# Look at the decompressor, and find the compressed data pos.
def pkl_decode_decompr(ctx):
    if not ctx.decompr.pos.val_known:
        return

    pos = ctx.decompr.pos.get()

    if byte_seq_matches(ctx, pos,
        b'\xfd\x8c\xdb\x53\x83\xc3', 0x3f):
        ctx.start_of_cmpr_data.set(ip_to_filepos(ctx,
            16 * getbyte(ctx, pos+6)))
        ctx.decompr.segclass.set('common')
    elif byte_seq_matches(ctx, pos,
            b'\xfd\x8c\xdb\x53\x81\xc3', 0x3f):
        ctx.start_of_cmpr_data.set(ip_to_filepos(ctx,
            16 * getu16(ctx, pos+6)))
        ctx.decompr.segclass.set('1.15')
    elif byte_seq_matches(ctx, pos, \
        b'\xfd\x5f\xc7\x85????\x4f\x4f\xbe??\x03\xf2'
        b'\x8b\xca\xd1\xe9\xf3', 0x3f):
        ctx.start_of_cmpr_data.set(2 + ip_to_filepos(ctx,
            getu16(ctx, pos+11)))
        ctx.decompr.segclass.set('v120small')
    elif byte_seq_matches(ctx, pos, \
        b'\xfd\x5f\x4f\x4f\xbe??\x03\xf2\x8b\xca\xd1\xe9\xf3', 0x3f):
        ctx.start_of_cmpr_data.set(2 + ip_to_filepos(ctx,
            getu16(ctx, pos+5)))
        ctx.decompr.segclass.set('v120small_old')
    else:
        ctx.errmsg = "Can't decode decompressor"
        return

def pkl_deduce_settings1(ctx):
    if (not ctx.start_of_cmpr_data.val_known) and ctx.is_beta.is_true():
        ctx.start_of_cmpr_data.set(ctx.codestart.get())

    if ctx.is_beta.is_true():
        ctx.approx_end_of_decompressor.set(ctx.codeend.get())
    elif ctx.start_of_cmpr_data.val_known:
        ctx.approx_end_of_decompressor.set(ctx.start_of_cmpr_data.get())

def pkl_deduce_settings2(ctx):
    if ctx.v120_compression.is_true():
        if ctx.decompr.segclass.val=='common':
            ctx.large_compression.set(True)
        elif ctx.decompr.segclass.val=='v120small' or \
            ctx.decompr.segclass.val=='v120small_old':
            ctx.large_compression.set(False)

# Detect 'extra' compression
def pkl_scan_decompr1(ctx):
    if not ctx.approx_end_of_decompressor.val_known:
        return
    if ctx.decompr.pos.val_known:
        startpos = ctx.decompr.pos.val+94
    elif ctx.is_beta.is_true() and ctx.codestart.val_known:
        # Kind of a hack. For beta files, I don't know how to find the best
        # place to search from.
        startpos = ctx.codestart.val
    else:
        return

    amt_to_scan = ctx.approx_end_of_decompressor.val - startpos

    # These signatures are very strict, but seem to still work.
    ok, foundpos = find_byte_seq(ctx, startpos, amt_to_scan,
        b'\xad\x95\xb2\x10\x72\x08\xa4\xd1\xed\x4a\x74')
    if ok:
        ctx.extra_compression.set(False)
        return

    # The critical part of this sig is [ac 32 c2 aa].
    ok, foundpos = find_byte_seq(ctx, startpos, amt_to_scan,
        b'\xad\x95\xb2\x10\x72\x0b\xac\x32\xc2\xaa\xd1\xed\x4a\x74')
    if ok:
        ctx.extra_compression.set(True)

def pkl_scan_decompr2(ctx):
    if not ctx.approx_end_of_decompressor.val_known:
        return

    # All files except v1.20 should have this pattern near the end of the
    # decompressor.
    endpos = ctx.approx_end_of_decompressor.get()
    amt_to_scan = 60  # 38 or slightly more is probably sufficient
    startpos = endpos-amt_to_scan
    ok, foundpos = find_byte_seq(ctx, startpos, amt_to_scan,
        b'\x01\x02\x00\x00\x03\x04\x05\x06'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x07\x08\x09\x0a\x0b')
    if ok:
        prec_b = getbyte(ctx, foundpos-1)
        if prec_b==0x09:
            ctx.large_compression.set(False)
            ctx.v120_compression.set(False)
            ctx.obfuscated_offsets.set(False)
        elif prec_b==0x18:
            ctx.large_compression.set(True)
            ctx.v120_compression.set(False)
            ctx.obfuscated_offsets.set(False)
        return

    # Files w/o the above pattern, but with the below pattern, are presumed
    # to be v1.20.
    amt_to_scan = 50  # 29 or slightly more is probably sufficient
    startpos = endpos-amt_to_scan
    ok, foundpos = find_byte_seq(ctx, startpos, amt_to_scan,
        b'\x33\xc0\x8b\xd8\x8b\xc8\x8b\xd0\x8b\xe8\x8b\xf0\x8b')
    if ok:
        ctx.v120_compression.set(True)

        # Detect "obfuscated offsets".

        # Strict patterns (v1.20 only):
        # d1 d3 80 eb 21 86 df fe c7 ac       8a d8 56 8b f7 2b f3 = not-obf.
        # d1 d3 80 eb 21 86 df fe c7 ac 34 ?  8a d8 56 8b f7 2b f3 = obf.off.

        startpos = ctx.decompr.pos.get() + 200
        amt_to_scan = endpos - startpos
        ok, foundpos = find_byte_seq_match(ctx, startpos, amt_to_scan,
            b'\xac\x34?\x8a', 0x3f)
        if ok:
            ctx.obfuscated_offsets.set(True)
            ctx.offsets_key.set(getbyte(ctx, foundpos+2))

        if not ctx.obfuscated_offsets.val_known:
            ok, foundpos = find_byte_seq(ctx, startpos, amt_to_scan,
                b'\xac\x8a\xd8')
            if ok:
                ctx.obfuscated_offsets.set(False)

def pkl_report(ctx):
    print('file:', ctx.infilename)
    print('file size:', ctx.file_size.getvalpr())
    print('exe code start:', ctx.codestart.getvalpr())
    print('exe code end:', ctx.codeend.getvalpr())
    if ctx.overlay_size.val_known:
        print('overlay size:', ctx.overlay_size.getvalpr())
    print('exe entry point:', ctx.entrypoint.getvalpr())
    print('reported version info:', ctx.ver_info.getvalpr_hex())
    print('intro pos:', ctx.entrypoint.getvalpr())
    print('intro class:', ctx.intro.segclass.val)
    print('beta:', ctx.is_beta.getvalpr_yesno())

    print('descrambler/copier pos:', ctx.position2.getvalpr())

    if ctx.is_scrambled.is_true_or_unk():
        print('descrambler pos:', ctx.descrambler.pos.getvalpr())
        print('descrambler class:', ctx.descrambler.segclass.val)

    print('copier pos:', ctx.copier.pos.getvalpr())
    print('copier class:', ctx.copier.segclass.val)
    if ctx.copier_subclass.val_known:
        print('copier subclass:', ctx.copier_subclass.getvalpr())

    print('error handler pos:', ctx.errorhandler.pos.getvalpr())
    #print('error handler class:', ctx.errorhandler.segclass.val)

    print('decompressor pos:', ctx.decompr.pos.getvalpr())
    print('decompressor class:', ctx.decompr.segclass.val)

    print('scrambled:', ctx.is_scrambled.getvalpr_yesno())
    if ctx.is_scrambled.is_true_or_unk():
        if ctx.scramble_algorithm.get()==1:
            s = 'XOR'
        elif ctx.scramble_algorithm.get()==2:
            s = 'ADD'
        else:
            s = '?'
        print(' scramble algorithm:', s)
        print(' initial key:', ctx.initial_key.getvalpr_hex())
        print(' scrambled section start:', ctx.scrambled_section_startpos.getvalpr())
        if ctx.is_scrambled.is_true() or ctx.scrambled_word_count>0:
            print(' num scrambled bytes:', ctx.scrambled_word_count*2)
        if ctx.pos_of_last_scrambled_word!=0:
            print(' scrambled end pos:', ctx.pos_of_last_scrambled_word+2)
        if ctx.previously_descrambled.is_true():
            print(' previously descrambled:', ctx.previously_descrambled.getvalpr_yesno())

    print('approx end of decompressor:', ctx.approx_end_of_decompressor.getvalpr())
    print("start of cmpr data:", ctx.start_of_cmpr_data.getvalpr())
    print('large:', ctx.large_compression.getvalpr_yesno())
    print('extra:', ctx.extra_compression.getvalpr_yesno())
    print('v1.20:', ctx.v120_compression.getvalpr_yesno())
    print('obfuscated offsets:', ctx.obfuscated_offsets.getvalpr_yesno())
    if ctx.obfuscated_offsets.is_true():
        print(' offsets key:', ctx.offsets_key.getvalpr_hex1())

    #if ctx.decompr.pos.val_known and ctx.approx_end_of_decompressor.val_known:
    #    print('decompressor size:', ctx.approx_end_of_decompressor.val - \
    #        ctx.decompr.pos.val)

def pkl_write_descrambled(ctx):
    if ctx.is_scrambled.is_false_or_unk():
        print("Can't descramble: Not a scrambled file.")
        return
    if ctx.previously_descrambled.is_true():
        print("Can't descramble: Already descrambled.")
        return
    print('Writing', ctx.outfilename)
    outf = open(ctx.outfilename, "wb")
    outf.write(ctx.blob)
    outf.close()
    print("** Use this descrambled file AT YOUR OWN RISK. **")

def main():
    ctx = context()

    if len(sys.argv)==2:
        ctx.infilename = sys.argv[1]
        ctx.want_descrambled = False
    elif len(sys.argv)==3:
        ctx.infilename = sys.argv[1]
        ctx.outfilename = sys.argv[2]
        if ctx.outfilename==ctx.infilename:
            raise Exception("Filenames are the same")
        ctx.want_descrambled = True
    else:
        print('usage: <pkla.py> <infile> [<outfile>]')
        print('With <outfile>, descrambles.')
        print('Without <outfile>, just analyzes.')
        return

    pkl_open_file(ctx)
    if ctx.errmsg=='':
        pkl_read_exe(ctx)
    if ctx.errmsg=='':
        pkl_decode_intro(ctx)
    if ctx.errmsg=='':
        pkl_detect_and_decode_descrambler(ctx)
    if ctx.errmsg=='':
        pkl_descramble(ctx)
    if ctx.errmsg=='':
        pkl_decode_copier(ctx)
    if ctx.errmsg=='':
        pkl_decode_decompr(ctx)
    pkl_deduce_settings1(ctx)
    if ctx.errmsg=='':
        pkl_scan_decompr1(ctx)
    if ctx.errmsg=='':
        pkl_scan_decompr2(ctx)
    pkl_deduce_settings2(ctx)
    pkl_report(ctx)
    if ctx.errmsg!='':
        print('Error:', ctx.errmsg)

    if ctx.errmsg=='' and ctx.want_descrambled:
        pkl_write_descrambled(ctx)

main()
