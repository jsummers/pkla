#!/usr/bin/python3

# pkstrings.py
# Version 2023.??.??
# by Jason Summers
#
# A script to decode text strings in some PKWARE executable files
#
# Terms of use: MIT license. See COPYING.txt.

import sys

default_nbytes_to_fingerprint = 16384

crc32_tab = [
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c ]

def mycrc32(data):
    crc = 0
    crc = crc ^ 0xffffffff

    for i in range(len(data)):
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] & 0xf)];
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] >> 4)];

    crc = crc ^ 0xffffffff
    return crc

class context:
    def __init__(ctx):
        ctx.errmsg = ''
        ctx.knownfiles = []
        ctx.items = []

class item:
    def __init__(self, file_id, endpos, ilen, bshift, id):
        self.file_id = file_id
        self.endpos = endpos
        self.ilen = ilen
        self.bshift = bshift
        self.item_id = id

class knownfile:
    def __init__(self, file_id, fingerprint):
        self.file_id = file_id
        self.fingerprint = fingerprint

def getbyte(ctx, offset):
    return ctx.blob[offset]

def getbyte_rel(ctx, offset):
    return ctx.blob[ctx.codestart + offset]

def getu16(ctx, offset):
    val = ctx.blob[offset] + 256*ctx.blob[offset+1]
    return val

def pks_add_new_knownfile(ctx, file_id, fingerprint):
    ff = knownfile(file_id, fingerprint)
    ctx.knownfiles.append(ff)

def pks_init_knownfiles(ctx):
    pks_add_new_knownfile(ctx, 'zipsfx0.90', 0x2400c6f5)
    pks_add_new_knownfile(ctx, 'zipsfx0.92', 0x8f7a3dd1)
    pks_add_new_knownfile(ctx, 'zipsfx1.01', 0xaa816885)
    pks_add_new_knownfile(ctx, 'pkunzip1.01', 0x7423970a)
    pks_add_new_knownfile(ctx, 'zip2exe1.01', 0xc843808c)
    pks_add_new_knownfile(ctx, 'pkzipfix1.01', 0x6a1c5464)

# (pks_add_new_item)
def pks_ii(ctx, file_id, offset, ilen, bshift, id):
    ii = item(file_id, offset, ilen, bshift, id)
    ctx.items.append(ii)

def pks_init_items(ctx):
    pks_ii(ctx, 'zipsfx0.90', 12804-512, 436, 6, 'send_money')
    pks_ii(ctx, 'zipsfx0.90', 13549-512, 744, 5, 'terms')
    pks_ii(ctx, 'zipsfx0.90', 14137-512, 587, 4, 'usage')
    pks_ii(ctx, 'zipsfx0.90', 14311-512, 173, 3, 'intro')
    pks_ii(ctx, 'zipsfx0.90', 14910-512, 416, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx0.90', 15052-512, 142, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx0.92', 12548-512, 436, 6, 'send_money')
    pks_ii(ctx, 'zipsfx0.92', 13293-512, 744, 5, 'terms')
    pks_ii(ctx, 'zipsfx0.92', 13881-512, 587, 4, 'usage')
    pks_ii(ctx, 'zipsfx0.92', 14055-512, 173, 3, 'intro')
    pks_ii(ctx, 'zipsfx0.92', 14654-512, 416, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx0.92', 14791-512, 137, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx1.01', 12900-512, 436, 6, 'send_money')
    pks_ii(ctx, 'zipsfx1.01', 13625-512, 724, 5, 'terms')
    pks_ii(ctx, 'zipsfx1.01', 14211-512, 585, 4, 'usage')
    pks_ii(ctx, 'zipsfx1.01', 14363-512, 151, 3, 'intro')
    pks_ii(ctx, 'zipsfx1.01', 14963-512, 421, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx1.01', 15101-512, 137, 0, 'strings_2')

    # Credit: Some of these items (the ones with hex numbers) were found
    # by Sergei Kolzun.
    pks_ii(ctx, 'pkunzip1.01', 0x45d0+0x1b6-512, 0x1b6, 3, 'send_money')
    pks_ii(ctx, 'pkunzip1.01', 0x4787+0x2da-512, 0x2da, 6, 'terms')
    pks_ii(ctx, 'pkunzip1.01', 0x4a62+0x361-512, 0x361, 4, 'usage')
    pks_ii(ctx, 'pkunzip1.01', 0x4dc4+0x8e-512, 0x8e, 5, 'intro')
    pks_ii(ctx, 'pkunzip1.01', 0x4f0e+0x89-512, 0x89, 0, 'strings_1')
    pks_ii(ctx, 'pkunzip1.01', 0x4fae+0x266-512, 0x266, 0, 'strings_2')

    pks_ii(ctx, 'zip2exe1.01', 0x1450+0x359-512, 0x359, 4, 'usage+terms')
    pks_ii(ctx, 'zip2exe1.01', 0x17aa+0x8d-512, 0x8d, 3, 'intro')
    pks_ii(ctx, 'zip2exe1.01', 0x1842+0x8d-512, 0x8d, 0, 'strings_1')
    pks_ii(ctx, 'zip2exe1.01', 0x18d0+0x89-512, 0x89, 0, 'strings_2')

    pks_ii(ctx, 'pkzipfix1.01', 0x1b70+0x3ce-512, 0x3ce, 3, 'usage+terms')
    pks_ii(ctx, 'pkzipfix1.01', 0x1f3f+0x71-512, 0x71, 5, 'intro')
    pks_ii(ctx, 'pkzipfix1.01', 0x2068+0x4e-512, 0x4e, 0, 'strings_1')
    pks_ii(ctx, 'pkzipfix1.01', 0x20b6+0x89-512, 0x89, 0, 'strings_2')

def pks_open_file(ctx):
    inf = open(ctx.infilename, "rb")
    ctx.blob = bytearray(inf.read())
    inf.close()
    ctx.file_size = len(ctx.blob)

def pks_read_main(ctx):
    ctx.ver_info_pos = 0
    sig = getu16(ctx, 0)
    if (sig!=0x5a4d and sig!=0x4d5a):
        ctx.errmsg = "Not an EXE file"
        return

    e_cblp = getu16(ctx, 2)
    e_cp = getu16(ctx, 4)

    e_cparhdr = getu16(ctx, 8)
    ctx.codestart = e_cparhdr*16

    if e_cblp==0:
        ctx.codeend = 512 * e_cp
    else:
        ctx.codeend = 512 * (e_cp-1) + e_cblp

    if ctx.codeend <= ctx.file_size:
        ctx.overlay_size = ctx.file_size - ctx.codeend
    else:
        ctx.errmsg = "Truncated EXE file"
        return

    if ctx.overlay_size > 0:
        ctx.overlay_pos = ctx.codeend

def pks_fingerprint(ctx):
    print(ctx.pfx+'code start:', ctx.codestart)
    print(ctx.pfx+'code end:', ctx.codeend)
    codelen = ctx.codeend - ctx.codestart
    if codelen > default_nbytes_to_fingerprint:
        nbytes_to_fingerprint = default_nbytes_to_fingerprint
    else:
        nbytes_to_fingerprint = codelen

    ctx.fingerprint = mycrc32(ctx.blob[ctx.codestart : \
        ctx.codestart+nbytes_to_fingerprint])
    print(ctx.pfx+'fingerprint: 0x%08x' % (ctx.fingerprint))

def pks_find_file_id(ctx):
    for i in range(len(ctx.knownfiles)):
        if ctx.knownfiles[i].fingerprint == ctx.fingerprint:
            ctx.file_id = ctx.knownfiles[i].file_id
            print(ctx.pfx+'file id:', ctx.file_id)
            return
    ctx.errmsg = 'Not a known file'

def getbyte_with_pos_and_key(ctx):
    b = getbyte_rel(ctx, ctx.pos)
    ctx.pos += 1
    b = b ^ ctx.key
    ctx.key = (ctx.key+0xff) & 0xff
    return b

def pks_decode_string_item(ctx, ii):
    print(ctx.pfx+'item: %s (%d-%d,%d)' % (ii.item_id, ii.endpos, ii.ilen, \
        ii.bshift))

    s = bytearray()
    ctx.pos = ii.endpos - ii.ilen
    ctx.key = ii.ilen & 0xff

    b0 = getbyte_with_pos_and_key(ctx)
    b1 = getbyte_with_pos_and_key(ctx)

    for i in range(ii.ilen):
        if ii.bshift==0:
            ob = b0
        else:
            ob = ((b0<<ii.bshift)&0xff) | (b1>>(8-ii.bshift))

        if ob==0x00:
            ob=0x0a

        s.append(ob)
        b0 = b1

        b1 = getbyte_with_pos_and_key(ctx)

    print(s.decode(encoding='cp437'))

def pks_process_strings(ctx):
    for i in range(len(ctx.items)):
        if ctx.items[i].file_id==ctx.file_id:
            pks_decode_string_item(ctx, ctx.items[i])

def usage():
    print('usage: pkstrings.py [options] <infile>')

def main():
    ctx = context()
    ctx.pfx = '### '

    xcount = 0
    for a1 in range(1, len(sys.argv)):
        arg = sys.argv[a1]
        if arg[0:1]=='-':
            continue
        xcount += 1
        if xcount==1:
            ctx.infilename = arg

    if xcount!=1:
        usage()
        return

    pks_init_knownfiles(ctx)
    pks_init_items(ctx)

    pks_open_file(ctx)

    if ctx.errmsg=='':
        pks_read_main(ctx)

    if ctx.errmsg=='':
        pks_fingerprint(ctx)

    if ctx.errmsg=='':
        pks_find_file_id(ctx)

    if ctx.errmsg=='':
        pks_process_strings(ctx)

    if ctx.errmsg!='':
        print(ctx.pfx+'Error:', ctx.errmsg)

main()
