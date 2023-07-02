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
    def __init__(self, file_id, fingerprint, warn1, warn2):
        self.file_id = file_id
        self.fingerprint = fingerprint
        self.warn1 = warn1
        self.warn2 = warn2

def getbyte(ctx, offset):
    return ctx.blob[offset]

def getbyte_rel(ctx, offset):
    return ctx.blob[ctx.codestart + offset]

def getu16(ctx, offset):
    val = ctx.blob[offset] + 256*ctx.blob[offset+1]
    return val

def pks_add_new_knownfile(ctx, file_id, fingerprint, warn1=False, warn2=False):
    ff = knownfile(file_id, fingerprint, warn1, warn2)
    ctx.knownfiles.append(ff)

def pks_init_knownfiles(ctx):
    pks_add_new_knownfile(ctx, 'zipsfx0.90', 0x2400c6f5)
    pks_add_new_knownfile(ctx, 'zipsfx0.92', 0x8f7a3dd1)
    pks_add_new_knownfile(ctx, 'zipsfx1.01', 0xaa816885)
    pks_add_new_knownfile(ctx, 'pkunzip1.01', 0x7423970a)
    pks_add_new_knownfile(ctx, 'zip2exe1.01', 0xc843808c)
    pks_add_new_knownfile(ctx, 'pkzipfix1.01', 0x6a1c5464)
    pks_add_new_knownfile(ctx, 'zipsfx2.04c', 0xde4cabec)
    pks_add_new_knownfile(ctx, 'zipsfx2.04e', 0x72b5183a)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g', 0xfae98b00)
    pks_add_new_knownfile(ctx, 'zipsfx2.50', 0x50b92554)
    pks_add_new_knownfile(ctx, 'zipsfx2.04c-reg', 0xfb93f922, warn2=True)
    pks_add_new_knownfile(ctx, 'zipsfx2.04e-reg', 0x6a2aad04, warn2=True)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g-reg', 0xad5aa1cf)
    pks_add_new_knownfile(ctx, 'zipsfx2.50-reg', 0xf6690492, warn2=True)

# (pks_add_new_item)
def pks_ii(ctx, file_id, offset, ilen, bshift, id):
    ii = item(file_id, offset, ilen, bshift, id)
    ctx.items.append(ii)

def pks_init_items(ctx):
    pks_ii(ctx, 'zipsfx0.90', 12804-512, 436, 6, 'reg_info')
    pks_ii(ctx, 'zipsfx0.90', 13549-512, 744, 5, 'terms')
    pks_ii(ctx, 'zipsfx0.90', 14137-512, 587, 4, 'usage')
    pks_ii(ctx, 'zipsfx0.90', 14311-512, 173, 3, 'intro')
    pks_ii(ctx, 'zipsfx0.90', 14910-512, 416, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx0.90', 15052-512, 142, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx0.92', 12548-512, 436, 6, 'reg_info')
    pks_ii(ctx, 'zipsfx0.92', 13293-512, 744, 5, 'terms')
    pks_ii(ctx, 'zipsfx0.92', 13881-512, 587, 4, 'usage')
    pks_ii(ctx, 'zipsfx0.92', 14055-512, 173, 3, 'intro')
    pks_ii(ctx, 'zipsfx0.92', 14654-512, 416, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx0.92', 14791-512, 137, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx1.01', 12900-512, 436, 6, 'reg_info')
    pks_ii(ctx, 'zipsfx1.01', 13625-512, 724, 5, 'terms')
    pks_ii(ctx, 'zipsfx1.01', 14211-512, 585, 4, 'usage')
    pks_ii(ctx, 'zipsfx1.01', 14363-512, 151, 3, 'intro')
    pks_ii(ctx, 'zipsfx1.01', 14963-512, 421, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx1.01', 15101-512, 137, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx2.04c', 15456+82,  450, 4, 'reg_info')
    pks_ii(ctx, 'zipsfx2.04c', 15667+46,  173, 4, 'intro')
    pks_ii(ctx, 'zipsfx2.04c', 16211+133, 630, 4, 'terms')
    pks_ii(ctx, 'zipsfx2.04c', 17103-128, 629, 4, 'usage')
    pks_ii(ctx, 'zipsfx2.04c', 17868-128, 686, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx2.04c', 18040-128, 152, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx2.04e', 15857+49,  450, 4, 'reg_info')
    pks_ii(ctx, 'zipsfx2.04e', 16044+37,  173, 4, 'intro')
    pks_ii(ctx, 'zipsfx2.04e', 16549+163, 630, 4, 'terms')
    pks_ii(ctx, 'zipsfx2.04e', 17102+241, 629, 4, 'usage')
    pks_ii(ctx, 'zipsfx2.04e', 18236-128, 686, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx2.04e', 18434-128, 152, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx2.04g', 15857+49,  450, 4, 'reg_info')
    pks_ii(ctx, 'zipsfx2.04g', 16044+37,  173, 4, 'intro')
    pks_ii(ctx, 'zipsfx2.04g', 16549+163, 630, 4, 'terms')
    pks_ii(ctx, 'zipsfx2.04g', 17102+241, 629, 4, 'usage')
    pks_ii(ctx, 'zipsfx2.04g', 18236-128, 686, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx2.04g', 18434-128, 152, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx2.04g-reg', 15331+112, 227, 4, 'reg_info')
    pks_ii(ctx, 'zipsfx2.04g-reg', 15595+24,  175, 4, 'intro')
    pks_ii(ctx, 'zipsfx2.04g-reg', 15974+123, 477, 4, 'terms')
    pks_ii(ctx, 'zipsfx2.04g-reg', 16517+210, 629, 4, 'usage')
    pks_ii(ctx, 'zipsfx2.04g-reg', 17598+150, 686, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx2.04g-reg', 17907+39,  152, 0, 'strings_2')

    pks_ii(ctx, 'zipsfx2.50', 17074+76,  606, 4, 'reg_info')
    pks_ii(ctx, 'zipsfx2.50', 17232+97,  178, 4, 'intro')
    pks_ii(ctx, 'zipsfx2.50', 17801+6,   477, 4, 'terms')
    pks_ii(ctx, 'zipsfx2.50', 18435+3,   630, 4, 'usage')
    pks_ii(ctx, 'zipsfx2.50', 19965-144, 779, 0, 'strings_1')
    pks_ii(ctx, 'zipsfx2.50', 20118-144, 152, 0, 'strings_2')

    pks_ii(ctx, 'pkunzip1.01', 17601+197, 438, 3, 'reg_info')
    pks_ii(ctx, 'pkunzip1.01', 18420+109, 730, 6, 'terms')
    pks_ii(ctx, 'pkunzip1.01', 19363+32,  865, 4, 'usage')
    pks_ii(ctx, 'pkunzip1.01', 19413+125, 142, 5, 'intro')
    pks_ii(ctx, 'pkunzip1.01', 19776+87,  137, 0, 'strings_1')
    pks_ii(ctx, 'pkunzip1.01', 20313+187, 614, 0, 'strings_2')

    pks_ii(ctx, 'zip2exe1.01', 5445+100, 857, 4, 'usage+terms')
    pks_ii(ctx, 'zip2exe1.01', 5682+5,   141, 3, 'intro')
    pks_ii(ctx, 'zip2exe1.01', 5794+45,  141, 0, 'strings_1')
    pks_ii(ctx, 'zip2exe1.01', 5943+34,  137, 0, 'strings_2')

    pks_ii(ctx, 'pkzipfix1.01', 7469+17, 974, 3, 'usage+terms')
    pks_ii(ctx, 'pkzipfix1.01', 7502+98, 113, 5, 'intro')
    pks_ii(ctx, 'pkzipfix1.01', 7804+58, 78,  0, 'strings_1')
    pks_ii(ctx, 'pkzipfix1.01', 7938+61, 137, 0, 'strings_2')

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
            if ctx.knownfiles[i].warn1:
                print(ctx.pfx+'Warning: Support for this file is incomplete')
            if ctx.knownfiles[i].warn2:
                print(ctx.pfx+'Warning: This file is recognized, but not supported')
            return

    sigtest = ctx.blob[30:36]
    if sigtest==b'PKLITE' or sigtest==b'PKlite':
        print(ctx.pfx+'Note: This looks like a PKLITE-compressed file.')
        print(ctx.pfx+'  It must be decompressed before it can be analyzed '+ \
            'with this script.')
        print(ctx.pfx+'  Suggest using Deark, with "-opt execomp" option.')

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

def pks_print_decoded_file(ctx, key, bshift):
    s = bytearray()
    ctx.pos = 0
    s_pos = ctx.pos
    ctx.key = key

    b0 = getbyte_with_pos_and_key(ctx)
    b1 = getbyte_with_pos_and_key(ctx)

    for i in range(ctx.codeend-ctx.codestart-10):
        if bshift==0:
            ob = b0
        else:
            ob = ((b0<<bshift)&0xff) | (b1>>(8-bshift))

        if (ob>=32 and ob<=126):
            s.append(ob)
            if len(s)>=240:
                print(s_pos, s.decode(encoding='cp437'))
                s = bytearray()
                s_pos = ctx.pos

        b0 = b1
        b1 = getbyte_with_pos_and_key(ctx)

    print(s.decode(encoding='cp437'))

def pks_process_strings(ctx):
    for i in range(len(ctx.items)):
        if ctx.items[i].file_id==ctx.file_id:
            pks_decode_string_item(ctx, ctx.items[i])

def usage():
    print('usage: pkstrings.py [options] <infile>')

def pks_process_file(ctx):
    pks_init_knownfiles(ctx)

    pks_open_file(ctx)

    if ctx.errmsg=='':
        pks_read_main(ctx)

    if ctx.errmsg=='':
        pks_fingerprint(ctx)

    if ctx.errmsg=='':
        pks_find_file_id(ctx)

    pks_init_items(ctx)

    if ctx.errmsg=='':
        pks_process_strings(ctx)

def pks_scan_1test(ctx, startkey, bshift):
    print(ctx.pfx+'TEST', startkey, bshift)
    pks_print_decoded_file(ctx, startkey, bshift)

def pks_scan_file(ctx):
    pks_open_file(ctx)
    if ctx.errmsg!='':
        return

    pks_read_main(ctx)
    if ctx.errmsg!='':
        return

    for sh in range(8):
        for key in range(256):
            pks_scan_1test(ctx, key, sh)

def main():
    ctx = context()
    ctx.pfx = '### '
    ctx.want_scan = False

    xcount = 0
    for a1 in range(1, len(sys.argv)):
        arg = sys.argv[a1]
        if arg[0:1]=='-':
            if arg=='-scan':
                ctx.want_scan = True
            continue
        xcount += 1
        if xcount==1:
            ctx.infilename = arg

    if xcount!=1:
        usage()
        return

    if ctx.want_scan:
        pks_scan_file(ctx)
    else:
        pks_process_file(ctx)

    if ctx.errmsg!='':
        print(ctx.pfx+'Error:', ctx.errmsg)

main()
