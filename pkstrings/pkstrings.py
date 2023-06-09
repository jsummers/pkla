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
    def __init__(self, endpos, ilen, bshift, id):
        #self.file_id = file_id
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

def getbyte_codeimage(ctx, offset):
    return ctx.codeimage[offset]

def getu16_exeheader(ctx, offset):
    val = ctx.exeheader[offset] + 256*ctx.exeheader[offset+1]
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
    pks_add_new_knownfile(ctx, 'zipsfx2.04c-reg', 0xfb93f922)
    pks_add_new_knownfile(ctx, 'zipsfx2.04e-reg', 0x6a2aad04)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g-reg', 0xad5aa1cf)
    pks_add_new_knownfile(ctx, 'zipsfx2.50-reg', 0xf6690492)
    pks_add_new_knownfile(ctx, 'pkzip2.04g', 0x42b0cb79, warn1=True)

# (pks_add_new_item)
def pks_ii(ctx, offset, ilen, bshift, id):
    ii = item(offset, ilen, bshift, id)
    ctx.items.append(ii)

def pks_init_items(ctx):
    if ctx.file_id=='zipsfx0.90':
        pks_ii(ctx, 12804-512, 436, 6, 'reg_info')
        pks_ii(ctx, 13549-512, 744, 5, 'terms')
        pks_ii(ctx, 14137-512, 587, 4, 'usage')
        pks_ii(ctx, 14311-512, 173, 3, 'intro')
        pks_ii(ctx, 14910-512, 416, 0, 'strings_1')
        pks_ii(ctx, 15052-512, 142, 0, 'strings_2')

    if ctx.file_id=='zipsfx0.92':
        pks_ii(ctx, 12548-512, 436, 6, 'reg_info')
        pks_ii(ctx, 13293-512, 744, 5, 'terms')
        pks_ii(ctx, 13881-512, 587, 4, 'usage')
        pks_ii(ctx, 14055-512, 173, 3, 'intro')
        pks_ii(ctx, 14654-512, 416, 0, 'strings_1')
        pks_ii(ctx, 14791-512, 137, 0, 'strings_2')

    if ctx.file_id=='zipsfx1.01':
        pks_ii(ctx, 12900-512, 436, 6, 'reg_info')
        pks_ii(ctx, 13625-512, 724, 5, 'terms')
        pks_ii(ctx, 14211-512, 585, 4, 'usage')
        pks_ii(ctx, 14363-512, 151, 3, 'intro')
        pks_ii(ctx, 14963-512, 421, 0, 'strings_1')
        pks_ii(ctx, 15101-512, 137, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.04c':
        pks_ii(ctx, 15456+82,  450, 4, 'reg_info')
        pks_ii(ctx, 15667+46,  173, 4, 'intro')
        pks_ii(ctx, 16211+133, 630, 4, 'terms')
        pks_ii(ctx, 17103-128, 629, 4, 'usage')
        pks_ii(ctx, 17868-128, 686, 0, 'strings_1')
        pks_ii(ctx, 18040-128, 152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.04c-reg':
        pks_ii(ctx, 15058+17, 227, 4, 'reg_info')
        pks_ii(ctx, 15163+88, 175, 4, 'intro')
        pks_ii(ctx, 15703+26, 477, 4, 'terms')
        pks_ii(ctx, 16303+56, 629, 4, 'usage')
        pks_ii(ctx, 17372+8, 686, 0, 'strings_1')
        pks_ii(ctx, 17476+76, 152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.04g' or ctx.file_id=='zipsfx2.04e':
        pks_ii(ctx, 15857+49,  450, 4, 'reg_info')
        pks_ii(ctx, 16044+37,  173, 4, 'intro')
        pks_ii(ctx, 16549+163, 630, 4, 'terms')
        pks_ii(ctx, 17102+241, 629, 4, 'usage')
        pks_ii(ctx, 18236-128, 686, 0, 'strings_1')
        pks_ii(ctx, 18434-128, 152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.04g-reg' or ctx.file_id=='zipsfx2.04e-reg':
        pks_ii(ctx, 15331+112, 227, 4, 'reg_info')
        pks_ii(ctx, 15595+24,  175, 4, 'intro')
        pks_ii(ctx, 15974+123, 477, 4, 'terms')
        pks_ii(ctx, 16517+210, 629, 4, 'usage')
        pks_ii(ctx, 17598+150, 686, 0, 'strings_1')
        pks_ii(ctx, 17907+39,  152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.50':
        pks_ii(ctx, 17074+76,  606, 4, 'reg_info')
        pks_ii(ctx, 17232+97,  178, 4, 'intro')
        pks_ii(ctx, 17801+6,   477, 4, 'terms')
        pks_ii(ctx, 18435+3,   630, 4, 'usage')
        pks_ii(ctx, 19965-144, 779, 0, 'strings_1')
        pks_ii(ctx, 20118-144, 152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.50-reg':
        pks_ii(ctx, 16740+37, 233, 4, 'contact')
        pks_ii(ctx, 16862+93, 178, 4, 'intro')
        pks_ii(ctx, 17488+99, 631, 4, 'terms+reg_info')
        pks_ii(ctx, 18157+61, 630, 4, 'usage')
        pks_ii(ctx, 19519+78, 779, 0, 'strings_1')
        pks_ii(ctx, 19674+76, 152, 0, 'strings_2')

    if ctx.file_id=='pkunzip1.01':
        pks_ii(ctx, 17601+197, 438, 3, 'reg_info')
        pks_ii(ctx, 18420+109, 730, 6, 'terms')
        pks_ii(ctx, 19363+32,  865, 4, 'usage')
        pks_ii(ctx, 19413+125, 142, 5, 'intro')
        pks_ii(ctx, 19776+87,  137, 0, 'strings_1')
        pks_ii(ctx, 20313+187, 614, 0, 'strings_2')

    if ctx.file_id=='zip2exe1.01':
        pks_ii(ctx, 5445+100, 857, 4, 'usage+terms')
        pks_ii(ctx, 5682+5,   141, 3, 'intro')
        pks_ii(ctx, 5794+45,  141, 0, 'strings_1')
        pks_ii(ctx, 5943+34,  137, 0, 'strings_2')

    if ctx.file_id=='pkzipfix1.01':
        pks_ii(ctx, 7469+17, 974, 3, 'usage+terms')
        pks_ii(ctx, 7502+98, 113, 5, 'intro')
        pks_ii(ctx, 7804+58, 78,  0, 'strings_1')
        pks_ii(ctx, 7938+61, 137, 0, 'strings_2')

    if ctx.file_id=='pkzip2.04g':
        pks_ii(ctx, 53268+47, 1707, 0, 'strings_1')
        pks_ii(ctx, 54523+35, 152,  0, 'strings_2')
        pks_ii(ctx, 55368+4,  814,  0, 'strings_3')

# Read the header and the code image into memory.
def pks_read_main2(ctx, inf):
    inf.seek(0, 2)
    ctx.file_size = inf.tell()
    inf.seek(0, 0)

    ctx.exeheader = bytearray(inf.read(64))

    sig = getu16_exeheader(ctx, 0)
    if (sig!=0x5a4d and sig!=0x4d5a):
        ctx.errmsg = "Not an EXE file"
        return

    e_cblp = getu16_exeheader(ctx, 2)
    e_cp = getu16_exeheader(ctx, 4)

    e_cparhdr = getu16_exeheader(ctx, 8)
    ctx.codestart = e_cparhdr*16

    if e_cblp==0:
        ctx.codeend = 512 * e_cp
    else:
        ctx.codeend = 512 * (e_cp-1) + e_cblp

    if ctx.codeend > ctx.file_size:
        ctx.errmsg = "Truncated EXE file"
        return

    inf.seek(ctx.codestart, 0);
    ctx.codeimage = bytearray(inf.read(ctx.codeend-ctx.codestart))
    inf.close()

def pks_read_main(ctx):
    inf = open(ctx.infilename, "rb")
    pks_read_main2(ctx, inf)
    inf.close()

def pks_fingerprint(ctx):
    print(ctx.pfx+'code start:', ctx.codestart)
    print(ctx.pfx+'code end:', ctx.codeend)
    codelen = ctx.codeend - ctx.codestart
    if codelen > default_nbytes_to_fingerprint:
        nbytes_to_fingerprint = default_nbytes_to_fingerprint
    else:
        nbytes_to_fingerprint = codelen

    ctx.fingerprint = mycrc32(ctx.codeimage[0 : nbytes_to_fingerprint])
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

    sigtest = ctx.exeheader[30:36]
    if sigtest==b'PKLITE' or sigtest==b'PKlite':
        print(ctx.pfx+'Note: This looks like a PKLITE-compressed file.')
        print(ctx.pfx+'  It must be decompressed before it can be analyzed '+ \
            'with this script.')
        print(ctx.pfx+'  Suggest using Deark, with "-opt execomp" option.')

    ctx.errmsg = 'Not a known file'

def getbyte_with_pos_and_key(ctx):
    b = getbyte_codeimage(ctx, ctx.pos)
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
    s_key = ctx.key

    b0 = getbyte_with_pos_and_key(ctx)
    b1 = getbyte_with_pos_and_key(ctx)

    for i in range(ctx.codeend-ctx.codestart-10):
        if bshift==0:
            ob = b0
        else:
            ob = ((b0<<bshift)&0xff) | (b1>>(8-bshift))

        if (ob>=32 and ob<=126):
            s.append(ob)
            if len(s)>=100:
                print(s_pos, s_key, s.decode(encoding='cp437'))
                s.clear()
                s_pos = ctx.pos
                s_key = ctx.key

        b0 = b1
        b1 = getbyte_with_pos_and_key(ctx)

    print(s.decode(encoding='cp437'))

def pks_process_strings(ctx):
    for i in range(len(ctx.items)):
        pks_decode_string_item(ctx, ctx.items[i])

def usage():
    print('usage: pkstrings.py [options] <infile>')

def pks_process_file(ctx):
    pks_init_knownfiles(ctx)

    if ctx.errmsg=='':
        pks_read_main(ctx)

    if ctx.errmsg=='':
        pks_fingerprint(ctx)

    if ctx.errmsg=='':
        pks_find_file_id(ctx)

    if ctx.errmsg=='':
        pks_init_items(ctx)

    if ctx.errmsg=='':
        pks_process_strings(ctx)

def pks_scan_1test(ctx, startkey, bshift):
    print(ctx.pfx+'TEST', startkey, bshift)
    pks_print_decoded_file(ctx, startkey, bshift)

def pks_scan_file(ctx):
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
