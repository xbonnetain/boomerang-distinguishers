#
# SMT model generator for Simon32 boomerangs
#
# Authors:
# Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria
#


import sys
from parse_SMT import *

def parse_key(keystream):
    k = keystream[:-81:-1]
    return str_to_idx(k)


def print_trails(d):
    end = False
    rd = 0
    e0 = 0
    e1 = 0
    if len(d) == 0:
        return
    print("kT : ", d["kT"])
    print("kB : ", d["kB"])

    ind = d["yT_0"]+d["xT_0"]
    while not end:
        end = True
        xT = " "*13
        yT = " "*19
        uxT = "0"*13
        uyT = "0"*19
        xB = " "*13
        yB = " "*19
        uxB = "0"*13
        uyB = "0"*19
        if f'uxT_{rd}' in d:
            uxT = d[f'uxT_{rd}']
        if f'uyT_{rd}' in d:
            uyT = d[f'uyT_{rd}']
        if f'uxB_{rd}' in d:
            uxB = d[f'uxB_{rd}']
        if f'uyB_{rd}' in d:
            uyB = d[f'uyB_{rd}']
        if f'xT_{rd}' in d:
            end = False
            xT = merge(d[f'xT_{rd}'], uxT)
            yT = merge(d[f'yT_{rd}'], uyT)
            e0+=1
        if f'xB_{rd}' in d:
            end = False
            xB = merge(d[f'xB_{rd}'], uxB)
            yB = merge(d[f'yB_{rd}'], uyB)
            outd=yB+xB
            e1+=1
        print(f"{rd}\t{yT} {xT} | {yB} {xB}")
        rd+=1

    rd-=2
    em = e0+e1-rd
    print(f"int indexk12{parse_key(d['kT'])};")
    print(f"int indexk13{parse_key(d['kB'])};")
    print(f"int indexdin{str_to_idx(ind)};")
    print(f"int indexdout{str_to_idx(outd)};")
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
