#!/usr/bin/python3

# pkla.py
# Version 2023.05.17+
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
    def getpr(self):
        if self.val_known:
            return self.val
        else:
            return '?'
    def getpr_hex(self):
        if self.val_known:
            return '0x%04x' % (self.val)
        else:
            return '?'
    def getpr_hex1(self):
        if self.val_known:
            return '0x%02x' % (self.val)
        else:
            return '?'
    def getpr_yesno(self):
        if self.val_known:
            if self.val:
                return 'yes'
            else:
                return 'no'
        else:
            return '?'
    def getpr_withrel(self, ctx):
        if self.val_known:
            rel_pos = self.val-ctx.entrypoint.val
            # The "ctx.ip+" part prints the offset part of the likely load
            # address. Useful if using a disassembler.
            if self.val >= ctx.entrypoint.val:
                return '%d (e%+d, :%04x)' % (self.val, rel_pos, ctx.ip+rel_pos)
            else:
                return '%d (c%+d)' % (self.val, self.val-ctx.codestart.val)
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
        ctx.entrypoint = pkla_number()
        ctx.ver_info = pkla_number()
        ctx.ver_reported = pkla_number()
        ctx.ip = 0
        ctx.reloc_tbl_end = 0
        ctx.codestart = pkla_number()
        ctx.codeend = pkla_number()
        ctx.has_orighdrcopy = pkla_bool()
        ctx.orighdrcopy_pos = pkla_number()
        ctx.orighdrcopy_size = pkla_number()
        ctx.overlay = pkla_segment()
        ctx.overlay_size = pkla_number()
        ctx.createdby = pkla_string()
        ctx.tags = []

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
        ctx.initial_DX = pkla_number()
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
        ctx.has_pklite_checksum = pkla_bool()
        ctx.pklite_checksum = pkla_number()
        ctx.checksum_calc = pkla_number()

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
    return ctx.codestart.val + (ip - 0x0100)

def bseq_match(ctx, pos1, vals, wildcard):
    if pos1+len(vals) > len(ctx.blob):
        return False

    for i in range(len(vals)):
        if vals[i] == wildcard:
            continue
        if ctx.blob[pos1+i] != vals[i]:
            return False

    return True

def bseq_exact(ctx, pos1, vals):
    if pos1+len(vals) > len(ctx.blob):
        return False

    for i in range(len(vals)):
        if ctx.blob[pos1+i] != vals[i]:
            return False

    return True

def find_bseq_match(ctx, startpos, maxbytes, vals, wildcard):
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

def find_bseq_exact(ctx, startpos, maxbytes, vals):
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

    num_relocs = getu16(ctx, 6)
    e_cparhdr = getu16(ctx, 8)
    ctx.codestart.set(e_cparhdr*16)

    if e_cblp==0:
        ctx.codeend.set(512 * e_cp)
    else:
        ctx.codeend.set(512 * (e_cp-1) + e_cblp)

    ctx.ip = getu16(ctx, 20)
    cs = gets16(ctx, 22)
    ctx.entrypoint.set(ctx.codestart.val + 16*cs + ctx.ip)

    reloc_tbl_start = getu16(ctx, 24)
    ctx.reloc_tbl_end = reloc_tbl_start + 4*num_relocs

    if ctx.codeend.val <= ctx.file_size.val:
        ctx.overlay_size.set(ctx.file_size.val - ctx.codeend.val)
    else:
        ctx.errmsg = "Truncated EXE file"
        return

    if ctx.overlay_size.val > 0:
        ctx.overlay.pos.set(ctx.codeend.val)

    ctx.ver_info.set(getu16(ctx, 28))
    ctx.ver_reported.set(ctx.ver_info.val & 0x0fff)

def pkl_decode_overlay(ctx):
    if ctx.overlay_size.val < 1:
        return
    if bseq_exact(ctx, ctx.overlay.pos.val, b'\x50\x4b\x03\x04'):
        ctx.overlay.segclass.set('ZIP')

# Decode the first part of the executable code, and
# find "position2": the position of the descrambler, or, if not scrambled,
# the position of the copier. This is usually right after the
# "Not enough memory" message.
def pkl_decode_intro(ctx):
    pos = ctx.entrypoint.val

    if bseq_match(ctx, pos, b'\xb8??\xba', 0x3f):
        ctx.initial_DX.set(getu16(ctx, pos+4))
    elif bseq_match(ctx, pos, b'\x50\xb8??\xba', 0x3f):
        ctx.initial_DX.set(getu16(ctx, pos+5))

    if bseq_match(ctx, pos,
        b'\x2e\x8c\x1e??\x8b\x1e??\x8c\xda??????\x72', 0x3f):
        ctx.intro.segclass.set('beta')
        ctx.is_beta.set(True)
    elif bseq_match(ctx, pos,
        b'\x2e\x8c\x1e??\xfc\x8c\xc8', 0x3f):
        ctx.intro.segclass.set("beta_lh")
        ctx.is_beta.set(True)
    elif bseq_match(ctx, pos,
        b'\xb8??\xba??\x8c\xdb\x03\xd8\x3b\x1e\x02\x00\x73', 0x3f):
        ctx.intro.segclass.set("1.00")
        ctx.is_scrambled.set(False)
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+15))
        ctx.position2.set(pos+16)
    elif bseq_match(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x73', 0x3f):
        ctx.intro.segclass.set("1.12")
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+14))
        ctx.position2.set(pos+15)
    elif bseq_match(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72', 0x3f):
        ctx.intro.segclass.set("1.14")
        ctx.position2.set(follow_1byte_jmp(ctx, pos+14))
        ctx.errorhandler.pos.set(pos+15)
    elif bseq_match(ctx, pos,
        b'\xb8??\xba??\x05\x00\x00\x3b\x2d\x73\x67\x72', 0x3f):
        ctx.intro.segclass.set("megalite")
        ctx.position2.set(follow_1byte_jmp(ctx, pos+14))
        ctx.errorhandler.pos.set(pos+15)
    elif bseq_match(ctx, pos,
        b'\x50\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72', 0x3f):
        ctx.intro.segclass.set("1.50")
        ctx.position2.set(follow_1byte_jmp(ctx, pos+15))
        ctx.errorhandler.pos.set(pos+16)
    elif bseq_match(ctx, pos,
        b'\x9c\xba??\x2d??\x81\xe1??\x81\xf3??\xb4??'
        b'\xb8??\xba??\x8c', 0x3f):
        ctx.intro.segclass.set("un2pack")
        ctx.is_scrambled.set(False)
        ctx.errorhandler.pos.set(follow_1byte_jmp(ctx, pos+18+15))
        ctx.position2.set(pos+18+16)
    elif bseq_match(ctx, pos,
        b'\x9c\xba??\x2d??\x81\xe1??\x81\xf3??\xb4', 0x3f):
        ctx.intro.segclass.set("un2pack_corrupt")

    if (not ctx.initial_key.val_known) and ctx.initial_DX.val_known:
        ctx.initial_key.set(ctx.initial_DX.val)

    if not ctx.intro.segclass.val_known:
        ctx.errmsg = 'Unknown PKLITE version, or not a PKLITE-compressed file'

    if ctx.intro.segclass.val_known:
        ctx.intro.pos.set(ctx.entrypoint.val)
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
    pos = ctx.position2.val

    if bseq_match(ctx, pos,
        b'\x2d\x20\x00\x8e\xd0\x2d??\x50\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x90\x49\x74?\xad\x92\x33\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.14scrambled')
        ctx.scramble_algorithm.set(1) # 33 = XOR
        ctx.pos_of_scrambled_word_count = pos+11
        pos_of_endpos_field = pos+14
        pos_of_jmp_field = pos + 22
    elif bseq_match(ctx, pos,
        b'\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.20var1') # e.g. pklite.exe 1.15
        ctx.scramble_algorithm.set(2)  # 03 = ADD
        ctx.pos_of_scrambled_word_count = pos+10
        pos_of_endpos_field = pos+13
        pos_of_jmp_field = pos + 20
    elif bseq_match(ctx, pos,
        b'\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe'
        b'\xfd\x90\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6', 0x3f):
        ctx.descrambler.segclass.set('1.20var1b') # e.g. pkzfind.exe
        ctx.scramble_algorithm.set(2)  # 03 = ADD
        ctx.pos_of_scrambled_word_count = pos+10
        pos_of_endpos_field = pos+13
        pos_of_jmp_field = pos + 21
    elif bseq_match(ctx, pos,
        b'\x59\x2d\x20\x00\x8e\xd0\x51??\x00\x50\x80\x3e'
        b'\x41\x01\xc3\x75\xe6\x52\xb8??\xbe??\x56\x56\x52\x50\x90'
        b'???????\x74???????\x33', 0x3f):
        ctx.descrambler.segclass.set('1.50scrambled')
        ctx.scramble_algorithm.set(1)
        ctx.pos_of_scrambled_word_count = pos+20
        pos_of_endpos_field = pos+23
        pos_of_jmp_field = pos + 38
    elif bseq_match(ctx, pos,
        b'\x2d\x20\x00????????????\xb9??\xbe????????\x74???\x03', 0x3f):
        ctx.descrambler.segclass.set('1.20var2') # e.g. pkzip.exe 2.04g
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+16
        pos_of_endpos_field = pos+19
        pos_of_jmp_field = pos+28
    elif bseq_match(ctx, pos,
        b'\x2d\x20\x00????????????\xb9??\xbe?????????\x74???\x03', 0x3f):
        ctx.descrambler.segclass.set('1.20pkzip204clike')
        ctx.scramble_algorithm.set(2)
        ctx.pos_of_scrambled_word_count = pos+16
        pos_of_endpos_field = pos+19
        pos_of_jmp_field = pos+29
    elif bseq_match(ctx, pos,
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
    elif bseq_match(ctx, pos,
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
    if ctx.scramble_algorithm.val==2:
        ctx.v120_compression.set(True)
    elif ctx.scramble_algorithm.val==1:
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

    if ctx.scramble_algorithm.val==2:
        alg_ADD = True
    else:
        alg_ADD = False

    for i in range(ctx.pos_of_last_scrambled_word+2 - \
        (ctx.scrambled_word_count*2), \
        ctx.pos_of_last_scrambled_word+2, 2):
        n1 = getu16(ctx, i)
        if i==ctx.pos_of_last_scrambled_word:
            n2 = ctx.initial_key.val
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
        pos = ctx.copier.pos.val
    elif ctx.is_scrambled.is_true():
        pos = ctx.scrambled_section_startpos.val
    else:
        pos = ctx.position2.val

    pos_of_decompr_pos_field = 0
    amt_to_scan = 60
    found = False

    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('common')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5\xca', 0x3f)
        if found:
            ctx.copier.segclass.set('1.50scrambled')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x57\xfc\xbe??\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('pklite2.01like')
            pos_of_decompr_pos_field = foundpos+8
    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\x57\xb9??\xbe??\xfc\xf3\xa5\xc3', 0x3f)
        if found:
            ctx.copier.segclass.set('1.20var1small')
            pos_of_decompr_pos_field = foundpos+5
    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x33\xff\x56\xbe??\xfc\xf2\xa5\xca', 0x3f)
        if found:
            ctx.copier.segclass.set('megalite')
            pos_of_decompr_pos_field = foundpos+7
    if not found:
        found, foundpos = find_bseq_match(ctx, pos, amt_to_scan,
            b'\xb9??\x2b\xff\x57\xbe??\xfc\xf3\xa5\xcb', 0x3f)
        if found:
            ctx.copier.segclass.set('un2pack')
            pos_of_decompr_pos_field = foundpos+7

    if found:
        ctx.copier_subclass.set('%s+%d' % (ctx.copier.segclass.val, \
            pos_of_decompr_pos_field-pos))
        ctx.copier.pos.set(pos)
        ctx.decompr.pos.set(ip_to_filepos(ctx, getu16(ctx, pos_of_decompr_pos_field)))
        if ctx.copier.pos.val==ctx.position2.val:
            # We found the copier at 'position2', so
            # there's definitely no scrambled section.
            ctx.is_scrambled.set(False)

# Look at the decompressor, and find the compressed data pos.
def pkl_decode_decompr(ctx):
    if not ctx.decompr.pos.val_known:
        return

    pos = ctx.decompr.pos.val

    if bseq_match(ctx, pos,
        b'\xfd\x8c\xdb\x53\x83\xc3', 0x3f):
        ctx.start_of_cmpr_data.set(ip_to_filepos(ctx,
            16 * getbyte(ctx, pos+6)))
        ctx.decompr.segclass.set('common')
    elif bseq_match(ctx, pos,
            b'\xfd\x8c\xdb\x53\x81\xc3', 0x3f):
        ctx.start_of_cmpr_data.set(ip_to_filepos(ctx,
            16 * getu16(ctx, pos+6)))
        ctx.decompr.segclass.set('1.15')
    elif bseq_match(ctx, pos, \
        b'\xfd\x5f\xc7\x85????\x4f\x4f\xbe??\x03\xf2'
        b'\x8b\xca\xd1\xe9\xf3', 0x3f):
        ctx.start_of_cmpr_data.set(2 + ip_to_filepos(ctx,
            getu16(ctx, pos+11)))
        ctx.decompr.segclass.set('v120small')
    elif bseq_match(ctx, pos, \
        b'\xfd\x5f\x4f\x4f\xbe??\x03\xf2\x8b\xca\xd1\xe9\xf3', 0x3f):
        ctx.start_of_cmpr_data.set(2 + ip_to_filepos(ctx,
            getu16(ctx, pos+5)))
        ctx.decompr.segclass.set('v120small_old')
    else:
        ctx.errmsg = "Can't decode decompressor"
        return

def pkl_deduce_settings1(ctx):
    if (not ctx.start_of_cmpr_data.val_known) and ctx.is_beta.is_true():
        ctx.start_of_cmpr_data.set(ctx.codestart.val)

    if ctx.is_beta.is_true():
        ctx.approx_end_of_decompressor.set(ctx.codeend.val)
    elif ctx.start_of_cmpr_data.val_known:
        ctx.approx_end_of_decompressor.set(ctx.start_of_cmpr_data.val)

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
    ok, foundpos = find_bseq_exact(ctx, startpos, amt_to_scan,
        b'\xad\x95\xb2\x10\x72\x08\xa4\xd1\xed\x4a\x74')
    if ok:
        ctx.extra_compression.set(False)
        return

    # The critical part of this sig is [ac 32 c2 aa].
    ok, foundpos = find_bseq_exact(ctx, startpos, amt_to_scan,
        b'\xad\x95\xb2\x10\x72\x0b\xac\x32\xc2\xaa\xd1\xed\x4a\x74')
    if ok:
        ctx.extra_compression.set(True)

# Detect:
# - large vs. small
# - v1.20 compression
# - offsets obfuscation
# - etc.
def pkl_scan_decompr2(ctx):
    if not ctx.approx_end_of_decompressor.val_known:
        return

    startpos = ctx.decompr.pos.val
    endpos = ctx.approx_end_of_decompressor.val
    amt_to_scan = endpos - startpos
    # TODO: Don't need to scan this much.
    ok, foundpos = find_bseq_match(ctx, startpos, amt_to_scan,
        b'\x3d??\x74?\x1f\xb4\x09\xba??\xcd\x21\xb8??\xcd\x21', 0x3f)
    if ok:
        ctx.has_pklite_checksum.set(True)
        ctx.pklite_checksum.set(getu16(ctx, foundpos+1))

    # All files except v1.20 should have this pattern near the end of the
    # decompressor.
    endpos = ctx.approx_end_of_decompressor.val
    amt_to_scan = 60  # 38 or slightly more is probably sufficient
    startpos = endpos-amt_to_scan
    ok, foundpos = find_bseq_exact(ctx, startpos, amt_to_scan,
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
    ok, foundpos = find_bseq_exact(ctx, startpos, amt_to_scan,
        b'\x33\xc0\x8b\xd8\x8b\xc8\x8b\xd0\x8b\xe8\x8b\xf0\x8b')
    if ok:
        ctx.v120_compression.set(True)

        # Detect "obfuscated offsets".

        # Strict patterns (v1.20 only):
        # d1 d3 80 eb 21 86 df fe c7 ac       8a d8 56 8b f7 2b f3 = not-obf.
        # d1 d3 80 eb 21 86 df fe c7 ac 34 ?  8a d8 56 8b f7 2b f3 = obf.off.

        startpos = ctx.decompr.pos.val + 200
        amt_to_scan = endpos - startpos
        ok, foundpos = find_bseq_match(ctx, startpos, amt_to_scan,
            b'\xac\x34?\x8a', 0x3f)
        if ok:
            ctx.obfuscated_offsets.set(True)
            ctx.offsets_key.set(getbyte(ctx, foundpos+2))

        if not ctx.obfuscated_offsets.val_known:
            ok, foundpos = find_bseq_exact(ctx, startpos, amt_to_scan,
                b'\xac\x8a\xd8')
            if ok:
                ctx.obfuscated_offsets.set(False)

def pkl_look_for_orighdrcopy(ctx):
    if ctx.extra_compression.is_true():
        ctx.has_orighdrcopy.set(False)
        return
    if ctx.extra_compression.is_true_or_unk():
        return

    ctx.has_orighdrcopy.set(False)  # Default

    if ctx.codestart.val - ctx.reloc_tbl_end < 26:
        return

    ctx.orighdrcopy_pos.set(ctx.reloc_tbl_end)
    orighdr_reloc_tbl_pos = getu16(ctx, ctx.orighdrcopy_pos.val+22)
    ctx.orighdrcopy_size.set(orighdr_reloc_tbl_pos-2)

    if ctx.orighdrcopy_size.val < 26:
        return

    if ctx.orighdrcopy_pos.val + ctx.orighdrcopy_size.val > \
        ctx.codestart.val:
        return

    # Check bytes-in-last-paragraph
    n = getu16(ctx, ctx.orighdrcopy_pos.val)
    if n>511:
        return

    # Number of 512-byte blocks
    n = getu16(ctx, ctx.orighdrcopy_pos.val+2)
    if n<1:
        return

    # Header size, in 16-byte units
    n = getu16(ctx, ctx.orighdrcopy_pos.val+6)
    if n<2:
        return

    ctx.has_orighdrcopy.set(True)

# The checksum is of the compressed data (not the decompressed data),
# including the compressed relocation table and the footer.
# My assumption is that in files with a checksum, the checksummed data
# both starts and ends at a file position that is a multiple of 16
# bytes. Such files add padding to the footer, if needed, to make this
# true.
def pkl_test_checksum(ctx):
    if not ctx.pklite_checksum.val_known:
        return
    if not ctx.initial_DX.val_known:
        return
    if not ctx.start_of_cmpr_data.val_known:
        return

    num_checksummed_words = (ctx.initial_DX.val * 16) // 2
    cksum = 0
    for i in range(num_checksummed_words):
        cksum += getu16(ctx, ctx.start_of_cmpr_data.val + 2*i)
        cksum = cksum % 65536
    ctx.checksum_calc.set(cksum)

def check_fake_v120(ctx):
    if bseq_exact(ctx, 30, b'PKLITE Copr. 1990-92 PKWARE'):
        ctx.tags.append('fake v1.20')

def pkl_fingerprint_extra(ctx):
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.12' and \
            ctx.copier_subclass.val=='common+20':
            if ctx.large_compression.val:
                x = getbyte(ctx, ctx.decompr.pos.val+257)
                if x==0xfa:
                    ctx.createdby.set('PKLITE 1.12 registered')
                    check_fake_v120(ctx)
                elif x==0x1e:
                    ctx.createdby.set('PKLITE 1.13 registered')
            else:
                x = getbyte(ctx, ctx.decompr.pos.val+223)
                if x==0xfa:
                    ctx.createdby.set('PKLITE 1.12 registered')
                    check_fake_v120(ctx)
                elif x==0x1e:
                    ctx.createdby.set('PKLITE 1.13 registered')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.is_scrambled.is_true() and \
            ctx.copier_subclass.val=='common+10' and \
            ctx.decompr.segclass.val=='common':
            ctx.createdby.set('PKLITE 1.14 registered')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.is_scrambled.is_true() and \
            ctx.copier_subclass.val=='common+10' and \
            ctx.decompr.segclass.val=='1.15':
            ctx.createdby.set('PKLITE 1.15 registered')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.50' and \
            ctx.descrambler.segclass.val=='1.50scrambled' and \
            ctx.copier_subclass.val=='common+10' and \
            ctx.decompr.segclass.val=='common':
            if bseq_exact(ctx, ctx.start_of_cmpr_data.val+304,
                b'\x3a\xef\x2c\x13\x2c\x0f\xf2\x63\x2c\x12\x2c\xed\xaa\xfc\x4b\x38'):
                ctx.createdby.set('ZIP2EXE 2.50 registered')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.50' and \
            ctx.is_scrambled.is_true() and \
            ctx.copier_subclass.val=='1.50scrambled+14' and \
            ctx.decompr.segclass.val=='common':
            ctx.createdby.set('PKLITE 1.50-2.01 registered')

def pkl_fingerprint_v120(ctx):
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.descrambler.segclass.val=='1.20var1' and \
            ctx.copier_subclass.val=='1.20var1small+7' and \
            ctx.decompr.segclass.val=='v120small':
            if bseq_exact(ctx, ctx.start_of_cmpr_data.val+306,
                b'\xec\xd5\x14\x32\xc0\x09\x43\xe1\xc7\x11\x8d\xc2\xec\x72\xfc\xcc'):
                ctx.createdby.set('ZIP2EXE 2.04c shareware')
            elif bseq_exact(ctx, ctx.start_of_cmpr_data.val+306,
                b'\x03\xf8\xd9\x18\x09\x43\xed\xcb\x15\x89\xc6\xcc\xbc\xf8\x7e\xf0'):
                ctx.createdby.set('ZIP2EXE 2.04c registered')
            elif bseq_exact(ctx, ctx.start_of_cmpr_data.val+12402,
                b'\x54\xb4\xc8\x5a\x9b\x6b\x46\x86\x67\x77\xcf\xdf\xce\x00\x00\x9f'):
                ctx.createdby.set('ZIP2EXE 2.04e shareware')
            elif bseq_exact(ctx, ctx.start_of_cmpr_data.val+12402,
                b'\xb3\xc9\x59\x9a\x64\x47\x85\x66\x70\xce\xdc\x00\x00\xdf\x80\x46'):
                ctx.createdby.set('ZIP2EXE 2.04g shareware')
            elif bseq_exact(ctx, ctx.start_of_cmpr_data.val+12402,
                b'\xed\xf8\xb0\xa0\x5c\xf8\xb8\x28\x5c\xdc\x41\x00\x00\x80\x6c\xad'):
                ctx.createdby.set('ZIP2EXE 2.04g registered')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.descrambler.segclass.val=='1.20var1b' and \
            ctx.copier_subclass.val=='1.20var1small+7' and \
            ctx.decompr.segclass.val=='v120small':
            if bseq_exact(ctx, ctx.start_of_cmpr_data.val+314,
                b'\x44\x43\xad\xb7\x9d\xb4\xfb\x0e\xa8\x23\xee\x4e\xa8\x97\xa8\x22'):
                ctx.createdby.set('ZIP2EXE 2.50 shareware')

def pkl_fingerprint_beta(ctx):
    dsize = ctx.codeend.val - ctx.entrypoint.val
    if ctx.large_compression.val:
        if dsize==648 or dsize==545: # 545 = loadhigh
            ctx.createdby.set('PKLITE 1.00beta')
    else:
        if dsize==468 or dsize==371: # 371 = loadhigh
            ctx.createdby.set('PKLITE 1.00beta')

def pkl_fingerprint_100_103(ctx):
    if not ctx.createdby.val_known:
        if ctx.large_compression.val:
            x = getbyte(ctx, ctx.copier.pos.val+17)
            if x==0x22:
                ctx.createdby.set('PKLITE 1.00')
            elif x==0x23:
                ctx.createdby.set('PKLITE 1.03')
    if not ctx.createdby.val_known:
        ctx.createdby.set('PKLITE 1.00-1.03')

def pkl_fingerprint(ctx):
    if not ctx.v120_compression.val_known:
        return
    if not ctx.extra_compression.val_known:
        return
    if not ctx.large_compression.val_known:
        return
    if not ctx.is_scrambled.val_known:
        return

    if ctx.v120_compression.is_true():
        pkl_fingerprint_v120(ctx)
        return
    if ctx.extra_compression.is_true():
        pkl_fingerprint_extra(ctx)
        return
    if ctx.is_beta.is_true():
        pkl_fingerprint_beta(ctx)
        return

    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.00' and \
            ctx.copier_subclass.val=='common+23':
            if bseq_exact(ctx, ctx.decompr.pos.val+9, b'\xbe\xfe\xff'):
                pkl_fingerprint_100_103(ctx)
            elif bseq_exact(ctx, ctx.decompr.pos.val+9, b'\x8c\xcd'):
                ctx.createdby.set('PKLITE 1.05')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.12' and \
            ctx.copier_subclass.val=='common+20':
            if ctx.large_compression.val:
                x = getbyte(ctx, ctx.decompr.pos.val+254)
                if x==0xfa:
                    ctx.createdby.set('PKLITE 1.12')
                    check_fake_v120(ctx)
                elif x==0x1e:
                    ctx.createdby.set('PKLITE 1.13')
            else:
                x = getbyte(ctx, ctx.decompr.pos.val+220)
                if x==0xfa:
                    ctx.createdby.set('PKLITE 1.12')
                    check_fake_v120(ctx)
                elif x==0x1e:
                    ctx.createdby.set('PKLITE 1.13')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.copier_subclass.val=='common+18' and \
            ctx.decompr.segclass.val=='common':
            ctx.createdby.set('PKLITE 1.14')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.14' and \
            ctx.copier_subclass.val=='common+19' and \
            ctx.decompr.segclass.val=='1.15':
            ctx.createdby.set('PKLITE 1.15')
    if not ctx.createdby.val_known:
        if ctx.intro.segclass.val=='1.50' and \
            ctx.copier_subclass.val=='common+20' and \
            ctx.decompr.segclass.val=='common':
            ctx.createdby.set('PKLITE 1.50-2.01')

def pkl_report(ctx):
    print('file size:', ctx.file_size.getpr())
    print('exe code start:', ctx.codestart.getpr())
    print('exe code end:', ctx.codeend.getpr())
    if ctx.overlay_size.val > 0:
        print('overlay pos:', ctx.overlay.pos.getpr())
    if ctx.overlay_size.val_known:
        print('overlay size:', ctx.overlay_size.getpr())
    if ctx.overlay_size.val > 0:
        print('overlay class:', ctx.overlay.segclass.getpr())

    print('has copy-or-orig-header:', ctx.has_orighdrcopy.getpr_yesno())
    if ctx.has_orighdrcopy.is_true():
        print(' copy-of-orig-header pos:', ctx.orighdrcopy_pos.getpr())
        if ctx.orighdrcopy_pos.val_known:
            print(' copy-of-orig-header size:', ctx.orighdrcopy_size.getpr())

    print('exe entry point:', ctx.entrypoint.getpr())
    print('reported version info:', ctx.ver_info.getpr_hex())
    print('intro pos:', ctx.entrypoint.getpr_withrel(ctx))
    print('intro class:', ctx.intro.segclass.val)
    print('beta:', ctx.is_beta.getpr_yesno())

    print('descrambler/copier pos:', ctx.position2.getpr_withrel(ctx))

    if ctx.is_scrambled.is_true_or_unk():
        print('descrambler pos:', ctx.descrambler.pos.getpr_withrel(ctx))
        print('descrambler class:', ctx.descrambler.segclass.val)

    print('copier pos:', ctx.copier.pos.getpr_withrel(ctx))
    print('copier class:', ctx.copier.segclass.val)
    if ctx.copier_subclass.val_known:
        print('copier subclass:', ctx.copier_subclass.getpr())

    print('error handler pos:', ctx.errorhandler.pos.getpr_withrel(ctx))
    #print('error handler class:', ctx.errorhandler.segclass.val)

    print('decompressor pos:', ctx.decompr.pos.getpr_withrel(ctx))
    print('decompressor class:', ctx.decompr.segclass.val)

    print('scrambled:', ctx.is_scrambled.getpr_yesno())
    if ctx.is_scrambled.is_true_or_unk():
        if ctx.scramble_algorithm.val==1:
            s = 'XOR'
        elif ctx.scramble_algorithm.val==2:
            s = 'ADD'
        else:
            s = '?'
        print(' scramble algorithm:', s)
        print(' initial key:', ctx.initial_key.getpr_hex())
        print(' scrambled section start:', ctx.scrambled_section_startpos.getpr_withrel(ctx))
        if ctx.is_scrambled.is_true() or ctx.scrambled_word_count>0:
            print(' num scrambled bytes:', ctx.scrambled_word_count*2)
        if ctx.pos_of_last_scrambled_word!=0:
            s_e_p = pkla_number()
            s_e_p.set(ctx.pos_of_last_scrambled_word+2)
            print(' scrambled end pos:', s_e_p.getpr_withrel(ctx))
        if ctx.previously_descrambled.is_true():
            print(' previously descrambled:', ctx.previously_descrambled.getpr_yesno())

    print('approx end of decompressor:', ctx.approx_end_of_decompressor.getpr_withrel(ctx))
    print("start of cmpr data:", ctx.start_of_cmpr_data.getpr_withrel(ctx))
    print('large:', ctx.large_compression.getpr_yesno())
    print('extra:', ctx.extra_compression.getpr_yesno())
    print('v1.20:', ctx.v120_compression.getpr_yesno())
    print('obfuscated offsets:', ctx.obfuscated_offsets.getpr_yesno())
    if ctx.obfuscated_offsets.is_true():
        print(' offsets key:', ctx.offsets_key.getpr_hex1())
    if ctx.has_pklite_checksum.val_known:
        print('has pklite checksum:', ctx.has_pklite_checksum.getpr_yesno())
        if ctx.pklite_checksum.val_known:
            print(' pklite checksum:', ctx.pklite_checksum.getpr_hex())
        print(' calculated checksum:', ctx.checksum_calc.getpr_hex())

    print('created by:', ctx.createdby.getpr())
    if len(ctx.tags) > 0:
        print('tags: [', end='')
        print('] ['.join(ctx.tags), end='')
        print(']')

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

    print('file:', ctx.infilename)
    pkl_open_file(ctx)
    if ctx.errmsg=='':
        pkl_read_exe(ctx)
    if ctx.errmsg=='':
        pkl_decode_overlay(ctx)
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
    if ctx.errmsg=='':
        pkl_look_for_orighdrcopy(ctx)
    pkl_deduce_settings2(ctx)
    if ctx.errmsg=='':
        pkl_test_checksum(ctx)
    if ctx.errmsg=='':
        pkl_fingerprint(ctx)
    pkl_report(ctx)
    if ctx.errmsg!='':
        print('Error:', ctx.errmsg)

    if ctx.errmsg=='' and ctx.want_descrambled:
        pkl_write_descrambled(ctx)

main()
