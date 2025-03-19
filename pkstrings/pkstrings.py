#!/usr/bin/python3

# pkstrings.py
# Version 2025.03.19+
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
        ctx.embedded_objects = []

class item:
    def __init__(self, endpos, ilen, bshift, id):
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

def gets16_exeheader(ctx, offset):
    val = getu16_exeheader(ctx, offset)
    if val >= 0x8000:
        val -= 0x10000
    return val

def pks_add_new_knownfile(ctx, file_id, fingerprint, warn1=False, warn2=False):
    ff = knownfile(file_id, fingerprint, warn1, warn2)
    ctx.knownfiles.append(ff)

def pks_init_knownfiles(ctx):
    pks_add_new_knownfile(ctx, 'zipsfx0.90', 0x2400c6f5)
    pks_add_new_knownfile(ctx, 'zipsfx0.92', 0x8f7a3dd1)
    pks_add_new_knownfile(ctx, 'zipsfx1.01', 0xaa816885)
    # (There is no zipsfx1.02.)
    pks_add_new_knownfile(ctx, 'zipsfx1.10', 0xf1ac0279, warn2=True)
    pks_add_new_knownfile(ctx, 'zipsfx1.10-export', 0x1afde3b7, warn2=True)
    pks_add_new_knownfile(ctx, 'zipsfx2.04c', 0xde4cabec)
    pks_add_new_knownfile(ctx, 'zipsfx2.04c-reg', 0xfb93f922)
    pks_add_new_knownfile(ctx, 'zipsfx2.04e', 0x72b5183a)
    pks_add_new_knownfile(ctx, 'zipsfx2.04e-reg', 0x6a2aad04)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g', 0xfae98b00)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g-swmkt', 0xc720b5aa)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g-reg', 0xad5aa1cf)
    pks_add_new_knownfile(ctx, 'zipsfx2.04g-reg-swmkt', 0xa451d121)
    pks_add_new_knownfile(ctx, 'zipsfx2.04-reg-french', 0xcb59c47f, warn2=True)
    pks_add_new_knownfile(ctx, 'pksfx2.49', 0x94fdb73c)
    pks_add_new_knownfile(ctx, 'zipsfx2.50', 0x50b92554)
    pks_add_new_knownfile(ctx, 'zipsfx2.50-reg', 0xf6690492)

    pks_add_new_knownfile(ctx, 'pkzip0.90', 0xa6762e60)
    pks_add_new_knownfile(ctx, 'pkzip0.92', 0x3d39db50)
    pks_add_new_knownfile(ctx, 'pkzip1.01', 0x6df9fa67)
    pks_add_new_knownfile(ctx, 'pkzip1.02', 0xaf358298)
    pks_add_new_knownfile(ctx, 'pkzip1.10', 0xbd3c0723)
    pks_add_new_knownfile(ctx, 'pkzip1.10-export', 0x16788efe)
    pks_add_new_knownfile(ctx, 'pkzip2.04c', 0x60788bda, warn1=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04c-reg', 0xb2c339bf, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04e', 0x75ea90e7, warn1=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04e-reg', 0x84cc47aa, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04g', 0x42b0cb79, warn1=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04g-swmkt', 0x8dd06dfa, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04g-reg', 0xc2ecee66, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.04-reg-french', 0xd24d95bc, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.06-IBM', 0xe2d25046, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzip2.50', 0x3a199e25, warn1=True)
    pks_add_new_knownfile(ctx, 'pkzip2.50-reg', 0x294e9e9f, warn2=True)

    pks_add_new_knownfile(ctx, 'pkunzip0.90', 0xa7edca44)
    pks_add_new_knownfile(ctx, 'pkunzip0.92', 0xa0bdf7d1)
    pks_add_new_knownfile(ctx, 'pkunzip1.01', 0x7423970a)
    pks_add_new_knownfile(ctx, 'pkunzip1.02', 0x9f66f20e)
    pks_add_new_knownfile(ctx, 'pkunzip1.10', 0x8a352fe4)
    pks_add_new_knownfile(ctx, 'pkunzip1.10-export', 0x4f000d45)
    pks_add_new_knownfile(ctx, 'pkunzip2.04c', 0x50280eea, warn1=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04c-reg', 0x5d9698f3, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04e', 0xb886fbb4, warn1=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04e-reg', 0xc9935d06, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04g', 0xb724c756, warn1=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04g-swmkt', 0xe2d89fba, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04g-reg', 0x5b8838d0, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.04-reg-french', 0x68e57e0c, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.06-IBM', 0x6b882239, warn2=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.50', 0xfb9a09f3, warn1=True)
    pks_add_new_knownfile(ctx, 'pkunzip2.50-reg', 0xc9d37588, warn2=True)

    pks_add_new_knownfile(ctx, 'zip2exe0.90', 0x027918a9)
    pks_add_new_knownfile(ctx, 'zip2exe0.92', 0xe26b9d22)
    pks_add_new_knownfile(ctx, 'zip2exe1.01', 0xc843808c)
    pks_add_new_knownfile(ctx, 'zip2exe1.02', 0xd7d91a43)
    pks_add_new_knownfile(ctx, 'zip2exe1.10', 0xb4c5611a)
    pks_add_new_knownfile(ctx, 'zip2exe1.10-export', 0x1fcda67d)
    pks_add_new_knownfile(ctx, 'zip2exe2.04c', 0x1b4f68ed)
    pks_add_new_knownfile(ctx, 'zip2exe2.04c-reg', 0xed7c8433)
    pks_add_new_knownfile(ctx, 'zip2exe2.04e', 0x4e6cba6b)
    pks_add_new_knownfile(ctx, 'zip2exe2.04e-reg', 0xc3cc0a87)
    pks_add_new_knownfile(ctx, 'zip2exe2.04g', 0xcda32810)
    pks_add_new_knownfile(ctx, 'zip2exe2.04g-swmkt', 0xb03af9d1)
    pks_add_new_knownfile(ctx, 'zip2exe2.04g-reg', 0x77fb9baf)
    pks_add_new_knownfile(ctx, 'zip2exe2.04-reg-french', 0x65a04c4a)
    pks_add_new_knownfile(ctx, 'zip2exe2.50', 0xec9b2d59)
    pks_add_new_knownfile(ctx, 'zip2exe2.50-reg', 0x2f201f50)

    # (pkzipfix introduced in v0.92.)
    pks_add_new_knownfile(ctx, 'pkzipfix0.92', 0x3a252515)
    pks_add_new_knownfile(ctx, 'pkzipfix1.01', 0x6a1c5464)
    # (There is no pkzipfix1.02.)
    pks_add_new_knownfile(ctx, 'pkzipfix1.10', 0x62d6ef8a)
    # (There is no unique pkzipfix1.10-export.)
    pks_add_new_knownfile(ctx, 'pkzipfix2.04c', 0xee8f66ad)
    pks_add_new_knownfile(ctx, 'pkzipfix2.04e', 0x97a12502)
    pks_add_new_knownfile(ctx, 'pkzipfix2.04g', 0xd466fb3b)
    # (There is no unique pkzipfix2.04g-reg.)
    pks_add_new_knownfile(ctx, 'pkzipfix2.04-reg-french', 0xe699e392, warn2=True)
    pks_add_new_knownfile(ctx, 'pkzipfix2.50', 0x816fdbf0)
    # (There is no unique pkzipfix2.50-reg.)

    pks_add_new_knownfile(ctx, 'putav2.04c-reg', 0x3aa17e83, warn2=True)
    pks_add_new_knownfile(ctx, 'putav2.04e-reg', 0xa9d0ba3d, warn2=True)
    pks_add_new_knownfile(ctx, 'putav2.04g-reg', 0x0c68b6ff, warn2=True)

    pks_add_new_knownfile(ctx, 'pkcfg2.04c-reg', 0x88c81c55)
    pks_add_new_knownfile(ctx, 'pkcfg2.04e-reg', 0xe4eff6c2)
    pks_add_new_knownfile(ctx, 'pkcfg2.04g-reg', 0x1b4feb35)
    pks_add_new_knownfile(ctx, 'pkcfg2.04-reg-french', 0x47409232)

# (pks_add_new_item)
def pks_ii(ctx, endpos, ilen, bshift, id):
    ii = item(endpos, ilen, bshift, id)
    ctx.items.append(ii)

# (pks_add_new_embedded_object)
def pks_eo(ctx, endpos, ilen, filename):
    ii = item(endpos, ilen, 0, '_embedded_object')
    ii.filename = filename
    ctx.embedded_objects.append(ii)

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

    # "Shareware Marketing" edition
    if ctx.file_id=='zipsfx2.04g-swmkt':
        pks_ii(ctx, 16067+7,   650, 4, 'reg_info')
        pks_ii(ctx, 16192+57,  173, 4, 'intro')
        pks_ii(ctx, 16844+36,  630, 4, 'terms')
        pks_ii(ctx, 17508+3,   629, 4, 'usage')
        pks_ii(ctx, 18233+51,  686, 0, 'strings_1')
        pks_ii(ctx, 18421+61,  152, 0, 'strings_2')

    if ctx.file_id=='zipsfx2.04g-reg' or ctx.file_id=='zipsfx2.04e-reg':
        pks_ii(ctx, 15331+112, 227, 4, 'reg_info')
        pks_ii(ctx, 15595+24,  175, 4, 'intro')
        pks_ii(ctx, 15974+123, 477, 4, 'terms')
        pks_ii(ctx, 16517+210, 629, 4, 'usage')
        pks_ii(ctx, 17598+150, 686, 0, 'strings_1')
        pks_ii(ctx, 17907+39,  152, 0, 'strings_2')

    # "Shareware Marketing" edition
    if ctx.file_id=='zipsfx2.04g-reg-swmkt':
        pks_ii(ctx, 15320+101, 237, 4, 'reg_info')
        pks_ii(ctx, 15535+62,  175, 4, 'intro')
        pks_ii(ctx, 16009+66,  477, 4, 'terms')
        pks_ii(ctx, 16647+58,  629, 4, 'usage')
        pks_ii(ctx, 17651+81,  686, 0, 'strings_1')
        pks_ii(ctx, 17852+78,  152, 0, 'strings_2')

    if ctx.file_id=='pksfx2.49':
        pks_ii(ctx, 17451+1, 300, 4, 'reg_info')
        pks_ii(ctx, 17550+77,  173, 4, 'intro')
        pks_ii(ctx, 18221+48, 641, 4, 'terms')
        pks_ii(ctx, 18898+1, 629, 4, 'usage')
        pks_ii(ctx, 19594+90, 686, 0, 'strings_1')
        pks_ii(ctx, 19811+25, 152, 0, 'strings_2')

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

    if ctx.file_id=='pkzip0.90':
        pks_ii(ctx, 22560+4,   436, 5, 'reg_info')
        pks_ii(ctx, 23305+6,   746, 3, 'terms')
        pks_ii(ctx, 24083+66,  837, 6, 'usage')
        pks_ii(ctx, 24282+8,   140, 4, 'intro')
        pks_ii(ctx, 25192+59,  719, 0, 'strings_2')
        pks_ii(ctx, 25385+11,  142, 0, 'strings_1')

    if ctx.file_id=='pkzip0.92':
        pks_ii(ctx, 23093+15,  436, 5, 'reg_info')
        pks_ii(ctx, 23778+77,  746, 3, 'terms')
        pks_ii(ctx, 24546+73,  763, 6, 'usage')
        pks_ii(ctx, 24668+92,  140, 4, 'intro')
        pks_ii(ctx, 25641+79,  730, 0, 'strings_2')
        pks_ii(ctx, 25767+90,  137, 0, 'strings_1')

    if ctx.file_id=='pkzip1.01':
        pks_ii(ctx, 26195+81,  436,  5, 'reg_info')
        pks_ii(ctx, 26985+18,  726,  3, 'terms')
        pks_ii(ctx, 28357+15,  1368, 6, 'usage')
        pks_ii(ctx, 28416+99,  142,  4, 'intro')
        pks_ii(ctx, 28930+103, 137,  0, 'strings_1')
        pks_ii(ctx, 30373+31,  1188, 0, 'strings_2')

    if ctx.file_id=='pkzip1.02':
        pks_ii(ctx, 26283+41,  436,  5, 'reg_info')
        pks_ii(ctx, 26985+66,  726,  3, 'terms')
        pks_ii(ctx, 28379+41,  1368, 6, 'usage')
        pks_ii(ctx, 28462+101, 142,  4, 'intro')
        pks_ii(ctx, 29259+14,  145,  0, 'strings_1')
        pks_ii(ctx, 30379+90,  1193, 0, 'strings_2')

    if ctx.file_id=='pkzip1.10':
        pks_ii(ctx, 29261+103, 436,  5, 'reg_info')
        pks_ii(ctx, 29988+70,  693,  3, 'terms')
        pks_ii(ctx, 31399+89,  1429, 6, 'usage')
        pks_ii(ctx, 31627+36,  174,  4, 'intro')
        pks_ii(ctx, 31851+16,  145,  0, 'strings_1')
        pks_ii(ctx, 33075+56,  1233, 0, 'strings_2')

    if ctx.file_id=='pkzip1.10-export':
        pks_ii(ctx, 28040+28,  436,  5, 'reg_info')
        pks_ii(ctx, 28707+55,  693,  3, 'terms')
        pks_ii(ctx, 30130+20,  1387, 6, 'usage')
        pks_ii(ctx, 30224+100, 173,  4, 'intro')
        pks_ii(ctx, 30431+96,  145,  0, 'strings_1')
        pks_ii(ctx, 31767+12,  1233, 0, 'strings_2')

    if ctx.file_id=='pkzip2.04c':
        pks_ii(ctx, 52641-368,  1593, 0, 'strings_1')
        pks_ii(ctx, 53690-368,  152,  0, 'strings_2')
        pks_ii(ctx, 54438-368,  748,  0, 'strings_3')

    if ctx.file_id=='pkzip2.04e':
        pks_ii(ctx, 53749+30, 1707, 0, 'strings_1')
        pks_ii(ctx, 54941+89, 152,  0, 'strings_2')
        pks_ii(ctx, 55771+73, 814,  0, 'strings_3')

    if ctx.file_id=='pkzip2.04g':
        pks_ii(ctx, 53268+47, 1707, 0, 'strings_1')
        pks_ii(ctx, 54523+35, 152,  0, 'strings_2')
        pks_ii(ctx, 55368+4,  814,  0, 'strings_3')

    if ctx.file_id=='pkzip2.50':
        pks_ii(ctx, 64659+46, 2043, 0, 'strings_1')
        pks_ii(ctx, 64808+66, 152,  0, 'strings_2')
        pks_ii(ctx, 65717+67, 876,  0, 'strings_3')

    if ctx.file_id=='pkunzip0.90':
        pks_ii(ctx, 14609+53,  438, 4, 'reg_info')
        pks_ii(ctx, 15311+102, 750, 5, 'terms')
        pks_ii(ctx, 16101+22,  709, 3, 'usage')
        pks_ii(ctx, 16179+87,  142, 6, 'intro')
        pks_ii(ctx, 16594+2,   142, 0, 'strings_1')
        pks_ii(ctx, 16999+93,  496, 0, 'strings_2')

    if ctx.file_id=='pkunzip0.92':
        pks_ii(ctx, 14729+93,  438, 4, 'reg_info')
        pks_ii(ctx, 15564+9,   750, 5, 'terms')
        pks_ii(ctx, 16219+64,  709, 3, 'usage')
        pks_ii(ctx, 16327+99,  142, 6, 'intro')
        pks_ii(ctx, 17045+83,  514, 0, 'strings_2')
        pks_ii(ctx, 17184+81,  137, 0, 'strings_1')

    if ctx.file_id=='pkunzip1.01':
        pks_ii(ctx, 17601+197, 438, 3, 'reg_info')
        pks_ii(ctx, 18420+109, 730, 6, 'terms')
        pks_ii(ctx, 19363+32,  865, 4, 'usage')
        pks_ii(ctx, 19413+125, 142, 5, 'intro')
        pks_ii(ctx, 19776+87,  137, 0, 'strings_1')
        pks_ii(ctx, 20313+187, 614, 0, 'strings_2')

    if ctx.file_id=='pkunzip1.02':
        pks_ii(ctx, 18275+51,  438, 3, 'reg_info')
        pks_ii(ctx, 19856+67,  865, 4, 'usage')
        pks_ii(ctx, 19021+36,  730, 6, 'terms')
        pks_ii(ctx, 20055+11,  142, 5, 'intro')
        pks_ii(ctx, 20832+58,  614, 0, 'strings_2')
        pks_ii(ctx, 21031+48,  145, 0, 'strings_1')

    if ctx.file_id=='pkunzip1.10':
        pks_ii(ctx, 19616+54,  438,  3, 'reg_info')
        pks_ii(ctx, 20291+77,  697,  6, 'terms')
        pks_ii(ctx, 21344+65,  1040, 4, 'usage')
        pks_ii(ctx, 21536+50,  177,  5, 'intro')
        pks_ii(ctx, 21683+114, 145,  0, 'strings_1')
        pks_ii(ctx, 22499+91,  772,  0, 'strings_2')

    if ctx.file_id=='pkunzip1.10-export':
        pks_ii(ctx, 18645+97,  438,  3, 'reg_info')
        pks_ii(ctx, 19344+96,  697,  6, 'terms')
        pks_ii(ctx, 20352+81,  992,  4, 'usage')
        pks_ii(ctx, 20546+64,  177,  5, 'intro')
        pks_ii(ctx, 20750+71,  145,  0, 'strings_1')
        pks_ii(ctx, 21504+98,  772,  0, 'strings_2')

    if ctx.file_id=='pkunzip2.04c':
        pks_ii(ctx, 33700+33,  713,  0, 'strings_1')
        pks_ii(ctx, 33936+54,  152,  0, 'strings_2')
        pks_ii(ctx, 34647+91,  748,  0, 'strings_3')

    if ctx.file_id=='pkunzip2.04e':
        pks_ii(ctx, 34399+30,  877,  0, 'strings_1')
        pks_ii(ctx, 34585+111, 152,  0, 'strings_2')
        pks_ii(ctx, 35428+82,  814,  0, 'strings_3')

    if ctx.file_id=='pkunzip2.04g':
        pks_ii(ctx, 34373+88,  877,  0, 'strings_1')
        pks_ii(ctx, 34588+94,  152,  0, 'strings_2')
        pks_ii(ctx, 35390+106, 815,  0, 'strings_3')

    if ctx.file_id=='pkunzip2.50':
        pks_ii(ctx, 40417+21,  1458, 0, 'strings_1')
        pks_ii(ctx, 40569+37,  152,  0, 'strings_2')
        pks_ii(ctx, 41433+71,  876,  0, 'strings_3')

    if ctx.file_id=='zip2exe0.90':
        pks_ii(ctx, 5332+85,   857, 4, 'usage+terms')
        pks_ii(ctx, 5496+63,   141, 3, 'intro')
        pks_ii(ctx, 5607+5,    40,  0, 'strings_1')
        pks_ii(ctx, 5725+29,   142, 0, 'strings_2')

    if ctx.file_id=='zip2exe0.92':
        pks_ii(ctx, 5386+47,   857, 4, 'usage+terms')
        pks_ii(ctx, 5501+74,   141, 3, 'intro')
        pks_ii(ctx, 5508+120,  40,  0, 'strings_1')
        pks_ii(ctx, 5720+45,   137, 0, 'strings_2')

    if ctx.file_id=='zip2exe1.01':
        pks_ii(ctx, 5445+100, 857, 4, 'usage+terms')
        pks_ii(ctx, 5682+5,   141, 3, 'intro')
        pks_ii(ctx, 5794+45,  141, 0, 'strings_1')
        pks_ii(ctx, 5943+34,  137, 0, 'strings_2')

    if ctx.file_id=='zip2exe1.02':
        pks_ii(ctx, 5462+83,  857, 4, 'usage+terms')
        pks_ii(ctx, 5620+67,  141, 3, 'intro')
        pks_ii(ctx, 5796+43,  141, 0, 'strings_1')
        pks_ii(ctx, 5926+59,  145, 0, 'strings_2')

    if ctx.file_id=='zip2exe1.10':
        pks_ii(ctx, 4342+54,   140, 4, 'intro')
        pks_ii(ctx, 5060+78,   741, 3, 'usage+terms')
        # Note: Any strings inside the "sfx" objects are artifacts
        # from the embedded SFX modules, not strings used by zip2exe. They
        # should not be listed here.
        pks_eo(ctx, 8598-512,  2934,  'sfx_mini.tmp')
        pks_eo(ctx, 21382-512, 12784, 'sfx_standard.tmp')
        pks_ii(ctx, 21099+15,  234, 0, 'strings_1')
        pks_ii(ctx, 21162+97,  145, 0, 'strings_2')

    if ctx.file_id=='zip2exe1.10-export':
        pks_ii(ctx, 4355+41,   140, 4, 'intro')
        pks_ii(ctx, 5041+97,   741, 3, 'usage+terms')
        pks_eo(ctx, 8598-512,  2934,  'sfx_mini.tmp')
        pks_eo(ctx, 20620-512, 12022, 'sfx_standard.tmp')
        pks_ii(ctx, 20332+20,  234, 0, 'strings_1')
        pks_ii(ctx, 20445+52,  145, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04c':
        pks_ii(ctx, 5028+72,  140, 4, 'intro')
        pks_ii(ctx, 5805+81,  784, 4, 'usage+terms')
        pks_eo(ctx, 21531-80,  15563, 'sfx_standard.tmp')
        pks_eo(ctx, 24534-80,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 24848+82,  476, 0, 'strings_1')
        pks_ii(ctx, 25145+109, 152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04c-reg':
        pks_ii(ctx, 5089+12,   141, 4, 'intro')
        pks_ii(ctx, 5878+8,    784, 4, 'usage+terms')
        pks_eo(ctx, 20910+120, 15142, 'sfx_standard.tmp')
        pks_eo(ctx, 23970+62,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 24439+69,  476, 0, 'strings_1')
        pks_ii(ctx, 24702+138, 152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04e':
        pks_ii(ctx, 23825+75,  140, 4, 'intro')
        pks_ii(ctx, 24657+31,  786, 4, 'usage+terms')
        pks_eo(ctx, 20825-80,  15769, 'sfx_standard.tmp')
        pks_eo(ctx, 23828-80,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 25154+12,  476, 0, 'strings_1')
        pks_ii(ctx, 25389+101, 152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04e-reg':
        pks_ii(ctx, 5087+30,   141, 4, 'intro')
        pks_ii(ctx, 5865+39,   786, 4, 'usage+terms')
        pks_eo(ctx, 21236+32,  15348, 'sfx_standard.tmp')
        pks_eo(ctx, 24194+76,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 24746+2,   476, 0, 'strings_1')
        pks_ii(ctx, 24986+94,  152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04g':
        pks_ii(ctx, 5033+83,   140, 4, 'intro')
        pks_ii(ctx, 5802+100,  784, 4, 'usage+terms')
        pks_eo(ctx, 21754-80,  15770, 'sfx_standard.tmp')
        pks_eo(ctx, 24756-80,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 25097+55,  476, 0, 'strings_1')
        pks_ii(ctx, 25369+107, 152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04g-swmkt':
        pks_ii(ctx, 5017+99,   140, 4, 'intro')
        pks_ii(ctx, 5897+5,    784, 4, 'usage+terms')
        pks_eo(ctx, 21758+133, 15987, 'sfx_standard.tmp')
        pks_eo(ctx, 24849+45,  3002,  'sfx_mini.tmp')
        pks_ii(ctx, 25356+14,  476, 0, 'strings_1')
        pks_ii(ctx, 25645+49,  152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.04g-reg':
        pks_ii(ctx, 5087+30,   141,  4, 'intro')
        pks_ii(ctx, 5863+39,   784,  4, 'usage+terms')
        pks_eo(ctx, 21236+17,  15349, 'sfx_standard.tmp')
        pks_eo(ctx, 24143+113, 3002,  'sfx_mini.tmp')
        pks_ii(ctx, 24723+9,   476,  0, 'strings_1')
        pks_ii(ctx, 25009+55,  152,  0, 'strings_2')

    if ctx.file_id=='zip2exe2.04-reg-french':
        pks_ii(ctx, 5051+69,   144, 4, 'intro')
        pks_ii(ctx, 5950+19,   847, 4, 'usage+terms')
        pks_eo(ctx, 22194+70,  16280, 'sfx_standard.tmp')
        pks_eo(ctx, 25198+74,  3008,  'sfx_mini.tmp')
        pks_ii(ctx, 25720+92,  532, 0, 'strings_1')
        pks_ii(ctx, 26059+125, 192, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.50':
        pks_ii(ctx, 26435+11,   142, 4, 'intro')
        pks_ii(ctx, 27521+86,  1159, 4, 'usage+terms')
        pks_eo(ctx, 23248-96,  16768, 'sfx_standard.tmp')
        pks_eo(ctx, 26398-96,  3150,  'sfx_mini.tmp')
        pks_ii(ctx, 28671+47,  476, 0, 'strings_1')
        pks_ii(ctx, 28864+14,  152, 0, 'strings_2')

    if ctx.file_id=='zip2exe2.50-reg':
        pks_ii(ctx, 26538+84,   142,  4, 'intro')
        pks_ii(ctx, 27705+12,   1093, 4, 'usage+terms')
        pks_eo(ctx, 23234+95,   16945, 'sfx_standard.tmp')
        pks_eo(ctx, 26394+86,   3150,  'sfx_mini.tmp')
        pks_ii(ctx, 28753+77,   476,  0, 'strings_1')
        pks_ii(ctx, 28941+49,   152,  0, 'strings_2')

    if ctx.file_id=='pkzipfix0.92':
        pks_ii(ctx, 6840+102, 974, 3, 'usage+terms')
        pks_ii(ctx, 6978+78, 113, 5, 'intro')
        pks_ii(ctx, 7285+34, 81,  0, 'strings_1')
        pks_ii(ctx, 7381+81, 142, 0, 'strings_2')

    if ctx.file_id=='pkzipfix1.01':
        pks_ii(ctx, 7469+17, 974, 3, 'usage+terms')
        pks_ii(ctx, 7502+98, 113, 5, 'intro')
        pks_ii(ctx, 7804+58, 78,  0, 'strings_1')
        pks_ii(ctx, 7938+61, 137, 0, 'strings_2')

    if ctx.file_id=='pkzipfix1.10':
        pks_ii(ctx, 6944+69, 117, 3, 'intro')
        pks_ii(ctx, 7921+75, 982, 5, 'usage+terms')
        pks_ii(ctx, 8108+40, 138, 0, 'strings_1')
        pks_ii(ctx, 8255+38, 145, 0, 'strings_2')

    if ctx.file_id=='pkzipfix2.04c':
        pks_ii(ctx, 7407+56,  119,  4, 'intro')
        pks_ii(ctx, 8392+51,  979,  4, 'usage+terms')
        pks_ii(ctx, 8576+22,  138,  0, 'strings_1')
        pks_ii(ctx, 8649+103, 152,  0, 'strings_2')

    if ctx.file_id=='pkzipfix2.04e':
        pks_ii(ctx, 7410+69,  119,  4, 'intro')
        pks_ii(ctx, 8388+71,  979,  4, 'usage+terms')
        pks_ii(ctx, 8511+103, 138,  0, 'strings_1')
        pks_ii(ctx, 8720+54,  152,  0, 'strings_2')

    if ctx.file_id=='pkzipfix2.04g':
        pks_ii(ctx, 7402+77,  119,  4, 'intro')
        pks_ii(ctx, 8386+73,  979,  4, 'usage+terms')
        pks_ii(ctx, 8517+97,  138,  0, 'strings_1')
        pks_ii(ctx, 8725+47,  152,  0, 'strings_2')

    if ctx.file_id=='pkzipfix2.50':
        pks_ii(ctx, 8253+75,  120,  4, 'intro')
        pks_ii(ctx, 9356+32,  1058, 4, 'usage+terms')
        pks_ii(ctx, 9534+65,  189,  0, 'strings_1')
        pks_ii(ctx, 9731+21,  152,  0, 'strings_2')

    if ctx.file_id=='pkcfg2.04c-reg':
        pks_ii(ctx, 26034+19, 3297, 0, 'strings_1')

    if ctx.file_id=='pkcfg2.04e-reg':
        pks_ii(ctx, 26269+39, 3330, 0, 'strings_1')

    if ctx.file_id=='pkcfg2.04g-reg':
        pks_ii(ctx, 26303+7,  3330, 0, 'strings_1')

    if ctx.file_id=='pkcfg2.04-reg-french':
        pks_ii(ctx, 27270+56, 3702, 0, 'strings_1')

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

    e_ip = getu16_exeheader(ctx, 20)
    e_cs = gets16_exeheader(ctx, 22)
    ctx.entrypoint_rel = 16*e_cs + e_ip  # Relative to codestart

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

    # In real PKWARE files, after PKLITE decompression if needed, I've never
    # seen the entry point to be close to the end of the code image.
    # If it is, we assume it's caused by a patch added by a PKLITE decompressor
    # like DISLITE or UNP.
    # The purpose of such a patch is to replicate the "PSP signature" feature
    # of PKLITE, but that's not important. What's important is that, for small
    # files, it will mess up our fingerprinting scheme if we're not careful.
    if (ctx.entrypoint_rel < nbytes_to_fingerprint) and \
        (ctx.entrypoint_rel < codelen) and \
        (ctx.entrypoint_rel+20 >= codelen):
        print(ctx.pfx+'found likely %d-byte patch at end of code' % \
            (codelen-ctx.entrypoint_rel))
        nbytes_to_fingerprint = ctx.entrypoint_rel

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

def pks_decode_item(ctx, ii, s, convertNUL):
    ctx.pos = ii.endpos - ii.ilen
    ctx.key = ii.ilen & 0xff

    b0 = getbyte_with_pos_and_key(ctx)
    b1 = getbyte_with_pos_and_key(ctx)

    for i in range(ii.ilen):
        if ii.bshift==0:
            ob = b0
        else:
            ob = ((b0<<ii.bshift)&0xff) | (b1>>(8-ii.bshift))

        if ob==0x00 and convertNUL:
            ob=0x0a

        s.append(ob)
        b0 = b1

        b1 = getbyte_with_pos_and_key(ctx)

def pks_decode_and_print_string_item(ctx, ii):
    print(ctx.pfx+'item: %s (%d-%d,%d)' % (ii.item_id, ii.endpos, ii.ilen, \
        ii.bshift))
    s = bytearray()
    pks_decode_item(ctx, ii, s, True)
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
                print("%d+%d %s" % (s_pos, s_key, s.decode(encoding='cp437')))
                s.clear()
                s_pos = ctx.pos
                s_key = ctx.key

        b0 = b1
        b1 = getbyte_with_pos_and_key(ctx)

    print(s.decode(encoding='cp437'))

def pks_decode_blob_to_file(ctx, ii):
    s = bytearray()
    pks_decode_item(ctx, ii, s, False)
    print(ctx.pfx+'Writing', ii.filename)
    outf = open(ii.filename, "wb")
    outf.write(s)
    outf.close()

def pks_process_strings(ctx):
    for i in range(len(ctx.items)):
        pks_decode_and_print_string_item(ctx, ctx.items[i])

    if len(ctx.embedded_objects)>0 and not ctx.want_embedded_objects:
        print(ctx.pfx+'This file has embedded objects. Use -e to extract them.')

def usage():
    print('usage: pkstrings.py [options] <infile>')

def pks_process_embedded_objects(ctx):
    for ii in ctx.embedded_objects:
        pks_decode_blob_to_file(ctx, ii)

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

    if ctx.errmsg=='' and not ctx.want_embedded_objects:
        pks_process_strings(ctx)

    if ctx.errmsg=='' and ctx.want_embedded_objects:
        pks_process_embedded_objects(ctx)

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
    ctx.want_embedded_objects = False

    xcount = 0
    for a1 in range(1, len(sys.argv)):
        arg = sys.argv[a1]
        if arg[0:1]=='-':
            if arg=='-scan':
                ctx.want_scan = True
            if arg=='-e':
                ctx.want_embedded_objects = True
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
