import re

def parse_line(d,line):
    l = line.split("))")[0][2:]
    [name, val] = l.split(" ")
    if val[:2] == "#x":
        val[0] = '0'
        val = bin(int(val,0))
    if val not in {"true", "false" }:
        val = val[2:]
    d[name] = val


def mask(v,u):
    if (u == '1'):
        return '?'
    return v

def merge(value, unknown):
    return "".join([  mask(a,b) for (a,b) in zip(value,unknown)  ])


def c_and(v,u):
    if v == ' ' or u == ' ':
        return ' '
    if v == '1':
        return u
    if u == '1':
        return v
    if u + v == '??':
        return '?'
    return '0'

def c_xor(u,v):
    if v == ' ' or u == ' ':
        return ' '
    if v == '?' or u == '?':
        return '?'
    return str(int(v) ^ int(u))

def rotate(l,i):
    return l[i:] + l[:i]


def differential(ones, unknown, length) :
    l = ['0']*length
    for i in ones:
        l[i] = '1'
    for i in unknown:
        l[i] = '?'
    return "".join(l)

def simon_bct(l1,l2):
    return "".join( [ c_xor(c_and(a,b),c_and(c,d)) for a,b,c,d in zip(l1,rotate(l2,7),l2,rotate(l1,7)) ])

def read_file(f):
    d = dict()
    print(f.readline())
    for line in f.readlines():
        parse_line(d,line)
    return d

def str_to_idx(s):
    idx = {i.start() for i in re.finditer(pattern='1',string=s)}
    return f"[{len(idx)}] = {idx}"

def bin_to_hex(s):
        return f"[{len(s)}] = {{{','.join([hex(int(x,2)) for x in s])}}}"
