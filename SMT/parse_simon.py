import sys
import re
from parse_SMT import *

def print_trails(d):
    end = False
    rd = 0
    e0 = 0
    e1 = 0
    lkt = []
    lkb = []
    if len(d) == 0:
        return
    #print("kT : ", d["kT"])
    #print("kB : ", d["kB"])
    ind = d["lftT_0"]+d["rgtT_0"]
    while not end:
        end = True
        lftT = " "*16
        rgtT = " "*16
        u_lftT = "0"*16
        u_rgtT = "0"*16
        lftB = " "*16
        rgtB = " "*16
        u_lftB = "0"*16
        u_rgtB = "0"*16
        kT = " "*16
        kB = " "*16
        if f'u_lftT_{rd}' in d:
            u_lftT = d[f'u_lftT_{rd}']
        if f'u_rgtT_{rd}' in d:
            u_rgtT = d[f'u_rgtT_{rd}']
        if f'u_lftB_{rd}' in d:
            u_lftB = d[f'u_lftB_{rd}']
        if f'u_rgtB_{rd}' in d:
            u_rgtB = d[f'u_rgtB_{rd}']
        if f'kT_{rd}' in d:
            kT = d[f'kT_{rd}']
            lkt.append(kT)
        if f'kB_{rd}' in d:
            kB = d[f'kB_{rd}']
            lkb.append(kB)
        if f'lftT_{rd}' in d:
            end = False
            lftT = merge(d[f'lftT_{rd}'], u_lftT)
            rgtT = merge(d[f'rgtT_{rd}'], u_rgtT)
            e0+=1
        if f'lftB_{rd}' in d:
            end = False
            lftB = merge(d[f'lftB_{rd}'], u_lftB)
            rgtB = merge(d[f'rgtB_{rd}'], u_rgtB)
            outd=lftB+rgtB
            e1+=1
        #        bct = simon_bct(lftT,lftB)
        bct = ""
        print(f"{rd}\t {kT}  {lftT} {rgtT} | {lftB} {rgtB}  {kB} || {bct}")
        rd+=1

    rd-=2
    em = e0+e1-rd
    print(f"u16 delta_k12{bin_to_hex(lkt[:4])};")
    print(f"u16 delta_k14{bin_to_hex(lkb[-4:])};")
    print(f"u32 delta_in = {hex(int(ind,2))};")
    print(f"u32 delta_out = {hex(int(outd,2))};")
    print(f"int nbrounds = {rd};")
    print(f'\nchar* tag = "{e0-em}-{em}-{e1-em}";')

def main():
    f = sys.stdin
    if len(sys.argv) > 1:
        f = open(sys.argv[1],"r")
    d = read_file(f)
    print_trails(d)
    f.close()


if __name__ == '__main__':
	main()
