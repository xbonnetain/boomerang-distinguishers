# Quartet finding model for Simon
#
# Authors:
# Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
#

import sys, argparse, parse_SMT


def shift(s,i):
	return f"((_ rotate_left {i}) {s})"

def i2v(i,l):
	# Yup.
	if i < 0:
		i=2**l+i
	return "#b{:0{l}b}".format(i,l=l)

def zero(l):
	return i2v(0,l)

def minus_one(l):
	return i2v(-1,l)

def key_args(key, i, key_length):
	return key+f" {key}".join(map(str,range(i,i+key_length)))


simon_keys = { 32 : [64], 48 : [72,96], 64 : [96,128], 96 : [96,144], 128 : [128,192,256] }


simon_z = {
	0 : [1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0],
	1 : [1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0],
	2 : [1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1],
	3 : [1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1],
	4 : [1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1]
	}


size_z = {
	32 : { 4 : 0 },
	48 : { 3 : 0, 4 : 1 },
	64 : { 3 : 2, 4 : 3 },
	96 : { 2 : 2, 3 : 3 },
	128 : { 2 : 2, 3 : 3, 4 : 4 }
	}

#Number of rounds of full version
test_round = {
        32 : { 4 : 32 },
        48 : { 3 : 36, 4 : 36 },
        64 : { 3 : 42, 4 : 44 },
        96 : { 2 : 52, 3 : 54 },
        128 : { 2 : 68, 3 : 69, 4 : 72 }
        }

#Test vectors: (Key, plaintext, ciphertext)
test_vectors = {
        32 : { 4 : ([0x1918,0x1110, 0x0908, 0x0100], (0x6565,0x6877), (0xc69b,0xe9bb)) },
        48 : { 3 : ([ 0x121110, 0x0a0908, 0x020100 ],( 0x612067, 0x6e696c ),( 0xdae5ac, 0x292cac)), 4 : ([ 0x1a1918, 0x121110, 0x0a0908, 0x020100 ],( 0x726963, 0x20646e ),( 0x6e06a5, 0xacf156)) },
        64 : { 3 : ([ 0x13121110, 0x0b0a0908, 0x03020100 ],( 0x6f722067, 0x6e696c63 ),( 0x5ca2e27f, 0x111a8fc8)), 4 : ([ 0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100 ],( 0x656b696c, 0x20646e75 ),( 0x44c8fc20, 0xb9dfa07a)) },
        96 : { 2 : ([ 0x0d0c0b0a0908, 0x050403020100 ],( 0x2072616c6c69, 0x702065687420 ),( 0x602807a462b4, 0x69063d8ff082)), 3 : ([ 0x151413121110, 0x0d0c0b0a0908, 0x050403020100 ],( 0x746168742074, 0x73756420666f ),( 0xecad1c6c451e, 0x3f59c5db1ae9)) },
        128 : { 2 : ([ 0x0f0e0d0c0b0a0908, 0x0706050403020100 ],( 0x6373656420737265, 0x6c6c657661727420 ),( 0x49681b1e1e54fe3f, 0x65aa832af84e0bbc)), 3 : ([ 0x1716151413121110, 0x0f0e0d0c0b0a0908, 0x0706050403020100 ],( 0x206572656874206e, 0x6568772065626972 ),( 0xc4ac61effcdc0d4f, 0x6c9c8d6e2597b85b)), 4 : ([ 0x1f1e1d1c1b1a1918, 0x1716151413121110, 0x0f0e0d0c0b0a0908, 0x0706050403020100 ],( 0x74206e69206d6f6f, 0x6d69732061207369 ),( 0x8d2b5579afc8a3a0, 0x3bf72a87efe7b868)) }
		}
def valid_simon(size,key):
	return size in simon_keys and key in simon_keys[size]

def main():
	parser = argparse.ArgumentParser(description ="Generates an SMT model for Simon boomerangs")
	parser.add_argument("-s", "--size", dest='size', type=int,default=32,choices=[32, 48, 64, 96, 128], help="block size of Simon (default 32)")
	parser.add_argument("-k", "--key", dest='key', type=int,default=64,choices=[64, 72, 96, 128, 144, 192, 256], help="key size of Simon (default 64)")
	parser.add_argument("-n", "--no-key-difference", dest='single', action='store_true', help="model a single-key boomerang")
	parser.add_argument("-i","--input_index", dest='ind', default=0,type=int, help="input difference bit")
	parser.add_argument("-o","--output_index", dest='outd', default=0,type=int,help="output difference bit")
	parser.add_argument("rounds",metavar='rounds', type=int, help="number of rounds")
	parser.add_argument("--check-file",dest='file',default=None,type=open,help="Check whether a boomerang from simonSMTpython is instanciable")
	parser.add_argument("--self-test",dest="test",action='store_true', help="Check against test vectors")
	args = parser.parse_args()

	if not valid_simon(args.size,args.key):
		print(f"Unsupported Simon version: {args.size}/{args.key}",file=sys.stderr)
		exit(1)
	print_query(args)
	print(f"\nGenerated boomerang constraints for Simon {args.size}/{args.key} {args.rounds} rounds input diff {hex(args.ind)} output diff {hex(args.outd)}",file=sys.stderr)



# definition of the Hamming weight function on nbr-bit numbers
def hamming_weight(nbr, fun_name="w_H"):
	i= 0
	call = "x"
	nb = nbr
	while(nb > 1):
		mask = "#b"+((("0"*(2**i)+"1"*(2**i))*nbr)[-nbr:])
		print(f" (define-fun {fun_name}{i} ((x (_ BitVec {nbr}))) (_ BitVec {nbr}) (bvadd (bvand x {mask} ) (bvand (bvlshr x {i2v(2**i,nbr)}) {mask} )))")
		call = f"({fun_name}{i} {call})"
		i=i+1
		nb = int(nb/2) + (i%2)
	print(f" (define-fun {fun_name} ((x (_ BitVec {nbr}))) (_ BitVec {nbr}) {call})")



def parse_file(f):
	d = parse_SMT.read_file(f)
	Nbr = 0
	while f"lftT_{Nbr}" in d:
		Nbr+=1
	while f"lftB_{Nbr}" in d:
		Nbr+=1
	Nbr-=1
	ind = int(d["lftT_0"]+d["rgtT_0"],2)
	outd = int(d[f"lftB_{Nbr}"]+d[f"rgtB_{Nbr}"],2)
	return (Nbr, ind, outd, d)

def print_query(args):


	size = args.size
	key = args.key

	if args.file is not None:
		(Nbr, ind, outd, keys) = parse_file(args.file)
	else:
		Nbr = args.rounds
		ind = 2**args.ind
		outd = 2**args.outd

	single = args.single

	branch_size = size // 2
	key_length = key // branch_size

	# constant for key schedule: z0 for Simon 32, and so on
	zi_full = simon_z[size_z[size][key_length]]

	zi = zi_full


	#Disable differentials and force number of rounds if in test mode
	if args.test:
		ind = 0
		outd = 0
		single = True
		Nbr = test_round[size][key_length]


	# -------------------------------- parameters for the solver  --------------------------------
	print("(set-logic QF_ABV)")
	print("(set-info :smt-lib-version 2.5)")
	print("(set-option :produce-models true)\n")

	# --------------------------------  Simon function  ------------------------------------------
	print(f"(define-fun simon (( l (_ BitVec {branch_size})) (r (_ BitVec {branch_size})) (k (_ BitVec {branch_size}))) (_ BitVec {branch_size}) (bvxor (bvxor (bvand {shift('l',8)} {shift('l',1)}) {shift('l',2)}) (bvxor r k)))")
	# -----------------------------------------------  KEY SCHEDULE --------------------------------------------
	# The 3 Simon key schedules
	print(f"(define-fun key_schedule_2 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor (bvxor ((_ rotate_right 4) k1) ((_ rotate_right 3) k1)) (bvxor k0 c)))")
	print(f"(define-fun key_schedule_3 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) (k2 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor (bvxor ((_ rotate_right 4) k2) ((_ rotate_right 3) k2)) (bvxor k0 c)))")
	print(f"(define-fun key_schedule_4 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) (k2 (_ BitVec {branch_size})) (k3 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor ((_ rotate_right 1)(bvxor ((_ rotate_right 3) k3) k1)) (bvxor (bvxor k0 c) (bvxor ((_ rotate_right 3) k3) k1))))")

	if key_length not in [2,3,4]:
		print("Unsupported key schedule",file=sys.stderr)
		exit(3)



	for i in range(Nbr-key_length):
		print(f"(declare-fun c_{i} () (_ BitVec {branch_size}))") 			# constant for key schedule


	# state values 0 to 3, left/right, for each round
	for i in range(Nbr+1):
		print(f"(declare-fun vl0_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vl1_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vl2_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vl3_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vr0_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vr1_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vr2_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun vr3_{i} () (_ BitVec {branch_size}))")

	# Key values 0 to 3, round application functions
	for i in range(Nbr):
		print(f"(declare-fun k0_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun k1_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun k2_{i} () (_ BitVec {branch_size}))")
		print(f"(declare-fun k3_{i} () (_ BitVec {branch_size}))")
		print(f"(assert (= vr0_{i+1} vl0_{i}))")
		print(f"(assert (= vr1_{i+1} vl1_{i}))")
		print(f"(assert (= vr2_{i+1} vl2_{i}))")
		print(f"(assert (= vr3_{i+1} vl3_{i}))")
		print(f"(assert (= vl0_{i+1} (simon vl0_{i} vr0_{i} k0_{i})))")
		print(f"(assert (= vl1_{i+1} (simon vl1_{i} vr1_{i} k1_{i})))")
		print(f"(assert (= vl2_{i+1} (simon vl2_{i} vr2_{i} k2_{i})))")
		print(f"(assert (= vl3_{i+1} (simon vl3_{i} vr3_{i} k3_{i})))")

    # Key schedule equalities
	for i in range(Nbr-key_length):
		print(f"(assert (= c_{i} {i2v(-4+zi[i % 62],branch_size)}))") # cst = fffd if bit = 1, fffc if bit = 0
		print(f"(assert (= k0_{i+key_length} (key_schedule_{key_length} c_{i} {key_args('k0_',i,key_length)} )))")
		print(f"(assert (= k1_{i+key_length} (key_schedule_{key_length} c_{i} {key_args('k1_',i,key_length)} )))")
		print(f"(assert (= k2_{i+key_length} (key_schedule_{key_length} c_{i} {key_args('k2_',i,key_length)} )))")
		print(f"(assert (= k3_{i+key_length} (key_schedule_{key_length} c_{i} {key_args('k3_',i,key_length)} )))")



	#Input/output differences definitions
	print(f"(declare-fun inl01 () (_ BitVec {branch_size}))")
	print(f"(declare-fun inl23 () (_ BitVec {branch_size}))")
	print(f"(declare-fun outl02 () (_ BitVec {branch_size}))")
	print(f"(declare-fun outl13 () (_ BitVec {branch_size}))")
	print(f"(declare-fun inr01 () (_ BitVec {branch_size}))")
	print(f"(declare-fun inr23 () (_ BitVec {branch_size}))")
	print(f"(declare-fun outr02 () (_ BitVec {branch_size}))")
	print(f"(declare-fun outr13 () (_ BitVec {branch_size}))")

	print(f"(assert (= inl01 inl23))")
	print(f"(assert (= outl02 outl13))")
	print(f"(assert (= inr01 inr23))")
	print(f"(assert (= outr02 outr13))")

	#Force Input/Output differences
	print(f"(assert (= inl01 {i2v(ind // 2**branch_size,branch_size)}))")
	print(f"(assert (= outl02 {i2v(outd // 2**branch_size,branch_size)}))")
	print(f"(assert (= inr01 {i2v(ind % 2**branch_size,branch_size)}))")
	print(f"(assert (= outr02 {i2v(outd % 2**branch_size,branch_size)}))")

	if args.file is None:
		# Single-key : 4 equal keys
		if single:
			for i in range(Nbr):
				print(f"(assert (= k1_{i} k0_{i}))")
				print(f"(assert (= k2_{i} k0_{i}))")
				print(f"(assert (= k3_{i} k0_{i}))")
		# Related-key : enforce key diffs of the form (delta_in, 0,...,0) and (0,...,0,delta_out)
		else:
			print(f"(assert (= k1_0 (bvxor k0_0 inr01)))")
			print(f"(assert (= k3_0 (bvxor k2_0 inr23)))")
			print(f"(assert (= k2_{Nbr-1} (bvxor k0_{Nbr-1} outl02)))")
			print(f"(assert (= k3_{Nbr-1} (bvxor k1_{Nbr-1} outl13)))")
			for i in range(1,key_length):
				print(f"(assert (= k1_{i} k0_{i}))")
				print(f"(assert (= k3_{i} k2_{i}))")
				print(f"(assert (= k2_{Nbr-1-i} k0_{Nbr-1-i}))")
				print(f"(assert (= k3_{Nbr-1-i} k1_{Nbr-1-i}))")
	else:
		#Key relations constraints from the SMT output
		for i in range(key_length):
			print(f"(assert (= (bvxor k0_{i} k1_{i}) {'#b'+keys[f'kT_{i}']})")
			print(f"(assert (= (bvxor k2_{i} k3_{i}) {'#b'+keys[f'kT_{i}']})")
			print(f"(assert (= (bvxor k0_{i} k2_{i}) {'#b'+keys[f'kB_{i}']})")
			print(f"(assert (= (bvxor k1_{i} k3_{i}) {'#b'+keys[f'kB_{i}']})")



	#Input/Output Boomerang constraints
	print(f"(assert (= inl01 (bvxor vl0_0 vl1_0)))")
	print(f"(assert (= inr01 (bvxor vr0_0 vr1_0)))")
	print(f"(assert (= inl23 (bvxor vl2_0 vl3_0)))")
	print(f"(assert (= inr23 (bvxor vr2_0 vr3_0)))")
	print(f"(assert (= outl02 (bvxor vl0_{Nbr} vl2_{Nbr})))")
	print(f"(assert (= outr02 (bvxor vr0_{Nbr} vr2_{Nbr})))")
	print(f"(assert (= outl13 (bvxor vl1_{Nbr} vl3_{Nbr})))")
	print(f"(assert (= outr13 (bvxor vr1_{Nbr} vr3_{Nbr})))")


	# Fix Key, input, output for the test. will be SAT if bug-free
	if args.test:
		(key, plain, cipher) = test_vectors[size][key_length]
		print(f"(assert (= vl0_0 {i2v(plain[0], branch_size)}))")
		print(f"(assert (= vr0_0 {i2v(plain[1], branch_size)}))")
		for i in range(key_length):
			print(f"(assert (= k0_{i} {i2v(key[-i-1], branch_size)}))")
		print(f"(assert (= vl0_{Nbr} {i2v(cipher[0], branch_size)}))")
		print(f"(assert (= vr0_{Nbr} {i2v(cipher[1], branch_size)}))")

	# -----------------------------------------------  RESOLUTION  --------------------------------------------


	# solve
	print("(check-sat)")
	print(f"(get-value ( inl01 ))", sep = '')
	print(f"(get-value ( inl23 ))", sep = '')
	print("(get-value ( outl02 ))", sep = '')
	print("(get-value ( outl13 ))", sep = '')
	print("(exit)")


if __name__ == '__main__':
	main()
