#
# SMT model generator for Simon (impossible) boomerangs
#
# Authors:
# Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
#
# Built upon the SMT model for Simon32 rotational-xor differentials from
# Improved Rotational-XOR Cryptanalysis of Simon-like Block Ciphers
# by Jinyu Lu, Yunwen Liu, Tomer Ashur, Bing Sun and Chao Li.
#





import sys, argparse


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


simon_keys = { 16 : [32], 32 : [64], 48 : [72,96], 64 : [96,128], 96 : [96,144], 128 : [128,192,256] }


simon_z = {
	0 : [1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0],
	1 : [1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0],
	2 : [1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1],
	3 : [1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1],
	4 : [1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1]
	}


size_z = {
	16 : { 4 : 0 }, # Toy cipher for experimental tests
	32 : { 4 : 0 },
	48 : { 3 : 0, 4 : 1 },
	64 : { 3 : 2, 4 : 3 },
	96 : { 2 : 2, 3 : 3 },
	128 : { 2 : 2, 3 : 3, 4 : 4 }
	}

def valid_simon(size,key):
	return size in simon_keys and key in simon_keys[size]

def main():
	parser = argparse.ArgumentParser(description ="Generates an SMT model for boomerang search on Simon with given probability.")
	parser.add_argument("-i", "--impossible", dest='impossible', action='store_true', help="model an impossible boomerang")
	parser.add_argument("-d","--rx_d", dest='rx_d', action='store_true', help="model a rotational-xor-differential boomerang")
	parser.add_argument("-x","--rotational", dest='rotational', action='store_true', help="model a rotational-xor boomerang")
	parser.add_argument("--rotation-index", dest='rotation', type=int, default=1, help="Rotation index (default 1)")
	parser.add_argument("--lower-rotation-index", dest='lower_rotation', type=int, default=None, help="Rotation index for the lower trail (default equal rotation index)")
	parser.add_argument("-r", "--start_round", dest='start_round', type=int,default=0,help="starting point of the distinguisher (only relevant with rotational-xor differences, default first round)")
	parser.add_argument("-n", "--no-key-difference", dest='single', action='store_true', help="model a single-key boomerang")
	parser.add_argument("-s", "--size", dest='size', type=int,default=32,choices=[16, 32, 48, 64, 96, 128], help="block size of Simon (default 32)")
	parser.add_argument("-k", "--key", dest='key', type=int,default=64,choices=[32, 64, 72, 96, 128, 144, 192, 256], help="key size of Simon (default 64)")
	parser.add_argument("--input_weight", dest='input_weight', type=int,default=-1, help="Force input difference weight")
	parser.add_argument("--output_weight", dest='output_weight', type=int,default=-1, help="Force output difference weight")
	parser.add_argument("top",metavar='E0', type=int, help="number of rounds in the top trail")
	parser.add_argument("middle",metavar='Em', type=int,help="number of intermingling trail rounds")
	parser.add_argument("bottom",metavar='E1', type=int, help="number of rounds in the bottom trail")
	parser.add_argument("proba",metavar='p', type=int,nargs='?',default=0,help="-log2 of target probability (default 0)")
	args = parser.parse_args()
	rotational = args.rotational or args.rx_d
	if args.impossible and args.rx_d:
		print("Impossible rotational-xor-differential boomerangs are not supported",file=sys.stderr)
		exit(1)
	if not valid_simon(args.size,args.key):
		print(f"Unsupported Simon version: {args.size}/{args.key}",file=sys.stderr)
		exit(1)

	if args.impossible and args.proba > 0:
		print("Warning: Impossible boomerang with proba < 1",file=sys.stderr)

	if args.single and (args.rotational or args.rx_d):
		print("Warning: Single key rotational-xor distinguisher",file=sys.stderr)

	if not rotational and args.start_round > 0:
		print("Warning: Irrelevant to start at a different round without rotations",file=sys.stderr)

	s = ""
	end= f"starting round {args.start_round}"
	if args.rx_d:
		s = "rotational-xor-differential"
	elif args.rotational:
		s = "rotational-xor"
	elif not args.single:
		s = "related-key"
		end=""
	else:
		s= "single-key"
		end = ""
	if args.impossible:
		s="impossible "+s
	print_query(args)
	print(f"\nGenerated {s} boomerang constraints for Simon {args.size}/{args.key} {args.top+args.middle+args.bottom} rounds (cut {args.top}+{args.middle}+{args.bottom}) objective {args.proba} {end}",file=sys.stderr)



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




def print_query(args):
	startingIndex = args.start_round
	NbrE0 = args.top
	NbrEm = args.middle
	NbrE1 = args.bottom
	obj = args.proba
	size = args.size
	key = args.key
	rotational = args.rotational or args.rx_d
	rotation_index=args.rotation
	rx_d = args.rx_d
	impossible = args.impossible
	single_key = args.single

	input_weight = args.input_weight
	output_weight = args.output_weight

	#The code support this options
	check_instanciable=False


	if not (rotational):
		rotation_index  = 0

	lower_rotation_index = rotation_index

	if rx_d:
		lower_rotation_index = 0
	elif args.lower_rotation is not None:
		lower_rotation_index = args.lower_rotation

	branch_size = size // 2
	key_length = key // branch_size

	# obj probability
	OBJ = bin(obj)[2:].zfill(branch_size)

	# constant for key schedule: z0 for Simon 32, and so on
	zi_full = simon_z[size_z[size][key_length]]

	zi = zi_full[startingIndex:]

	# -------------------------------- parameters for the solver  --------------------------------
	print("(set-logic QF_ABV)")
	print("(set-info :smt-lib-version 2.5)")
	print("(set-option :produce-models true)\n")

	# --------------------------------  creating variables  --------------------------------------

	# definition of the Hamming weight function (w_H x)
	hamming_weight(branch_size)


	for i in range(NbrE0+NbrEm+NbrE1):										#  TOP and BOTTOM key
		print(f"(declare-fun kT_{i} () (_ BitVec {branch_size}))")			#  for key schedule
		print(f"(declare-fun kB_{i} () (_ BitVec {branch_size}))")			#  for key schedule


	for i in range(NbrE0+NbrEm+NbrE1-key_length):
		print(f"(declare-fun c_{i} () (_ BitVec {branch_size}))") 			# constant for key schedule
	
	
	#									TOP TRAIL

	for i in range(NbrE0+NbrEm):										#				indices (0) to (NbrE0 + NbrEm -1 )
		print(f"(declare-fun lftT_{i} () (_ BitVec {branch_size}))")	# lft, diff
		print(f"(declare-fun rgtT_{i} () (_ BitVec {branch_size}))")	# rgt, diff

		print(f"(declare-fun u_lftT_{i} () (_ BitVec {branch_size}))")	# known lft, diff
		print(f"(declare-fun u_rgtT_{i} () (_ BitVec {branch_size}))")	# known rgt, diff

	for i in range(NbrE0+NbrEm-1):
		print(f"(declare-fun keyT_{i} () (_ BitVec {branch_size}))")	# key, diff
		print(f"(declare-fun wrT_{i} () (_ BitVec {branch_size}))")		#  HW of z, ie proba of 1 round

	for i in range(NbrE0):
		print(f"(declare-fun dT_{i} () (_ BitVec {branch_size}))")			# = \gamma from https://ia.cr/2015/145
		print(f"(declare-fun varibitsT_{i} () (_ BitVec {branch_size}))")	#  varibits notation from https://ia.cr/2015/145
		print(f"(declare-fun doublebitsT_{i} () (_ BitVec {branch_size}))")	#  doublebits notation from https://ia.cr/2015/145
		print(f"(declare-fun zT_{i} () (_ BitVec {branch_size}))")			#  z = varibits + doublebits


	#									BOTTOM TRAIL

	for i in range(NbrEm+NbrE1):												# BOTTOM TRAIL = Em + E1   	 indices (NbrE0 + 1) to (NbrE0 + NbrEm + NbrE1 )
		print(f"(declare-fun lftB_{i+NbrE0+1} () (_ BitVec {branch_size}))")	# lft, diff
		print(f"(declare-fun rgtB_{i+NbrE0+1} () (_ BitVec {branch_size}))")	# rgt, diff

		print(f"(declare-fun u_lftB_{i+NbrE0+1} () (_ BitVec {branch_size}))")	# known lft, diff
		print(f"(declare-fun u_rgtB_{i+NbrE0+1} () (_ BitVec {branch_size}))")	# known rgt, diff


	for i in range(NbrEm+NbrE1-1):
		print(f"(declare-fun keyB_{i+NbrE0+1} () (_ BitVec {branch_size}))")	# key, diff
		print(f"(declare-fun wrB_{i+NbrE0+1} () (_ BitVec {branch_size}))")			#  HW of z, ie proba of 1 round

	for i in range(NbrE1):
		print(f"(declare-fun dB_{i+NbrE0+NbrEm} () (_ BitVec {branch_size}))")	# = \gamma from https://ia.cr/2015/145
		print(f"(declare-fun varibitsB_{i+NbrE0+NbrEm} () (_ BitVec {branch_size}))")	#  varibits notation from https://ia.cr/2015/145
		print(f"(declare-fun doublebitsB_{i+NbrE0+NbrEm} () (_ BitVec {branch_size}))")	#  doublebits notation from https://ia.cr/2015/145
		print(f"(declare-fun zB_{i+NbrE0+NbrEm} () (_ BitVec {branch_size}))")	#  z = varibits + doublebits


	#									MIDDLE TRAIL
	if impossible:
		print(f"(declare-fun summarymask () (_ BitVec {branch_size*NbrEm}))")
		print(f"(assert (not (= summarymask {i2v(0,branch_size*NbrEm)})))")


	for i in range(NbrEm-1):

		print(f"(declare-fun PayT_{i+NbrE0} () (_ BitVec {branch_size}))")
		print(f"(declare-fun PayB_{i+NbrE0+1} () (_ BitVec {branch_size}))")

		print(f"(declare-fun computableT_{i+NbrE0} () (_ BitVec {branch_size}))")
		print(f"(declare-fun computableB_{i+NbrE0+1} () (_ BitVec {branch_size}))")

		print(f"(declare-fun chosenValueT_{i+NbrE0} () (_ BitVec {branch_size}))")
		print(f"(declare-fun chosenValueB_{i+NbrE0+1} () (_ BitVec {branch_size}))")

		print(f"(declare-fun computedValueT_{i+NbrE0} () (_ BitVec {branch_size}))")
		print(f"(declare-fun computedValueB_{i+NbrE0+1} () (_ BitVec {branch_size}))")

		print(f"(declare-fun doublebitsT_{i+NbrE0} () (_ BitVec {branch_size}))")
		print(f"(declare-fun doublebitsB_{i+NbrE0+1} () (_ BitVec {branch_size}))")

	if impossible:
		for i in range(NbrEm):
			print(f"(declare-fun constraintmask_{i+NbrE0} () (_ BitVec {branch_size}))")
			print(f"(assert (= ((_ extract {branch_size*(i+1)-1} {branch_size*i}) summarymask ) constraintmask_{i+NbrE0} ))")


	#Force non-trivial trail
	if not rotational and not impossible:
		print(f"(assert (or (or (not (= lftT_{0} {zero(branch_size)})) (not (= rgtT_{0} {zero(branch_size)}))) (or (or (not (= {zero(branch_size)} kT_{0})) (not (= {zero(branch_size)} kT_{1}))) (or (not (= {zero(branch_size)} kT_{2})) (not (= {zero(branch_size)} kT_{3}))))))")
		print(f"(assert (or (or (not (= lftB_{NbrEm+NbrE1} {zero(branch_size)})) (not (= rgtB_{NbrEm+NbrE1} {zero(branch_size)}))) (or (or (not (= {zero(branch_size)} kB_{0})) (not (= {zero(branch_size)} kB_{1}))) (or (not (= {zero(branch_size)} kB_{2})) (not (= {zero(branch_size)} kB_{3}))))))")

	if rx_d :
		print(f"(assert (or (not (= lftB_{NbrE0+NbrEm+NbrE1} {zero(branch_size)})) (not (= rgtB_{NbrE0+NbrEm+NbrE1} {zero(branch_size)}))))")


	# -----------------------------------------------  KEY SCHEDULE --------------------------------------------

	# key schedule for the top and bottom keys, for all the rounds
	# gives the kT and kB

	print(f"(define-fun key_schedule_2 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor (bvxor ((_ rotate_right 4) k1) ((_ rotate_right 3) k1)) (bvxor k0 c)))")
	print(f"(define-fun key_schedule_3 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) (k2 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor (bvxor ((_ rotate_right 4) k2) ((_ rotate_right 3) k2)) (bvxor k0 c)))")
	print(f"(define-fun key_schedule_4 ( (c (_ BitVec {branch_size})) (k0 (_ BitVec {branch_size})) (k1 (_ BitVec {branch_size})) (k2 (_ BitVec {branch_size})) (k3 (_ BitVec {branch_size})) ) (_ BitVec {branch_size}) (bvxor ((_ rotate_right 1)(bvxor ((_ rotate_right 3) k3) k1)) (bvxor (bvxor k0 c) (bvxor ((_ rotate_right 3) k3) k1))))")

	if key_length not in [2,3,4]:
		print("Unsupported key schedule",file=sys.stderr)
		exit(3)

	if not single_key:
		for i in range(NbrE0+NbrEm+NbrE1-key_length):
			print(f"(assert (= c_{i} {i2v(-4+zi[i % 31],branch_size)}))") # cst = fffd if bit = 1
			print(f"(assert (= kT_{i+key_length} (key_schedule_{key_length} (bvxor ((_ rotate_left {rotation_index}) c_{i}) c_{i}) {key_args('kT_',i,key_length)} )))")
			if not rx_d:
				print(f"(assert (= kB_{i+key_length} (key_schedule_{key_length} (bvxor ((_ rotate_left {rotation_index}) c_{i}) c_{i}) {key_args('kB_',i,key_length)} )))")


	for i in range(NbrE0+NbrEm+NbrE1):
		if rx_d or single_key:
			print(f"(assert ( = {zero(branch_size)} kB_{i}))")
		if single_key:
			print(f"(assert ( = {zero(branch_size)} kT_{i}))")


	for i in range(NbrE0+NbrEm-1):
		print("(assert (=  keyT_",i,"  kT_",i,"))", sep = '')
	for i in range(NbrEm+NbrE1-1):
		print("(assert (=  keyB_",i+NbrE0+1,"  kB_",i+NbrE0+1,"))", sep = '')


	if input_weight > -1:
		print(f"(assert (= (bvadd (w_H lftT_0) (w_H rgtT_0)) {i2v(input_weight,branch_size)}))")

	if output_weight > -1:
		print(f"(assert (= (bvadd (w_H lftB_{NbrE0+NbrEm+NbrE1}) (w_H rgtB_{NbrE0+NbrEm+NbrE1})) {i2v(output_weight,branch_size)}))")



	if check_instanciable:
		#normal simon Round
		print(f"(define-fun simon (( l (_ BitVec {branch_size})) (r (_ BitVec {branch_size})) (k (_ BitVec {branch_size}))) (_ BitVec {branch_size}) (bvxor (bvxor (bvand {shift('l',8)} {shift('l',1)}) {shift('l',2)}) (bvxor r k)))")


		for i in range(NbrE0+NbrEm+NbrE1+1):
			print(f"(declare-fun vl0_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vl1_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vl2_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vl3_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vr0_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vr1_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vr2_{i} () (_ BitVec {branch_size}))")
			print(f"(declare-fun vr3_{i} () (_ BitVec {branch_size}))")

		for i in range(NbrE0+NbrEm+NbrE1):
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

			print(f"(assert (= k1_{i} (bvxor kT_{i} {shift(f'k0_{i}',rotation_index)})))")
			print(f"(assert (= k3_{i} (bvxor kT_{i} {shift(f'k2_{i}',rotation_index)})))")
			if not rx_d:
				print(f"(assert (= k1_{i} (bvxor kB_{i} {shift(f'k2_{i}',lower_rotation_index)})))")
			else:
				print(f"(assert (= k2_{i} k0_{i}))")

		#Comment this line to validate the markov cipher assumption
		# for i in range(NbrE0+NbrEm+NbrE1-key_length):
		# 	print(f"(assert( = k0_{i+key_length} (key_schedule_{key_length} c_{i} {key_args('k0_',i,key_length)})))")

		for i in range(NbrE0+NbrEm):
			print(f"(assert (= (bvor u_lftT_{i} vl1_{i}) (bvor u_lftT_{i} (bvxor {shift(f'vl0_{i}',rotation_index)} lftT_{i}))))")
			print(f"(assert (= (bvor u_lftT_{i} vl3_{i}) (bvor u_lftT_{i} (bvxor {shift(f'vl2_{i}',rotation_index)} lftT_{i}))))")
			print(f"(assert (= (bvor u_rgtT_{i} vr1_{i}) (bvor u_rgtT_{i} (bvxor {shift(f'vr0_{i}',rotation_index)} rgtT_{i}))))")
			print(f"(assert (= (bvor u_rgtT_{i} vr3_{i}) (bvor u_rgtT_{i} (bvxor {shift(f'vr2_{i}',rotation_index)} rgtT_{i}))))")
		for i in range(NbrE0+1,NbrE0+NbrEm+NbrE1+1):
			print(f"(assert (= (bvor u_lftB_{i} vl1_{i}) (bvor {shift(f'u_lftB_{i}',rotation_index-lower_rotation_index)} (bvxor {shift(f'vl2_{i}',lower_rotation_index)} {shift(f'lftB_{i}',rotation_index-lower_rotation_index)}))))")
			print(f"(assert (= (bvor u_lftB_{i} vl3_{i}) (bvor u_lftB_{i} (bvxor {shift(f'vl0_{i}',lower_rotation_index)} lftB_{i}))))")
			print(f"(assert (= (bvor u_rgtB_{i} vr1_{i}) (bvor {shift(f'u_rgtB_{i}',rotation_index-lower_rotation_index)} (bvxor {shift(f'vr2_{i}',lower_rotation_index)} {shift(f'rgtB_{i}',rotation_index-lower_rotation_index)}))))")
			print(f"(assert (= (bvor u_rgtB_{i} vr3_{i}) (bvor u_rgtB_{i} (bvxor {shift(f'vr0_{i}',lower_rotation_index)} rgtB_{i}))))")


	# -----------------------------------------------  TOP TRAIL --------------------------------------------

	# state differences, top trail in E0
	for i in range(NbrE0):
		print("(assert (=  rgtT_",i+1,"  lftT_",i," ))", sep = '') # copied branch   rgt i+1 = lft i
		print("(assert (=  varibitsT_",i,"  (bvor  ((_ rotate_left 8) lftT_",i,") ((_ rotate_left 1)lftT_",i,"))))", sep = '') # varibits computation
		print(f"(assert (=  doublebitsT_{i} (bvand (bvand (bvxor ((_ rotate_left 8) lftT_{i}) {minus_one(branch_size)}) ((_ rotate_left 1)lftT_{i})) ((_ rotate_left 15) lftT_{i}))))")#  doublebits computation
		print(f"(assert (=  {zero(branch_size)} (bvand  (bvxor varibitsT_{i} {minus_one(branch_size)})  dT_{i})))")	# cond 1 thm 3
		print(f"(assert (=  {zero(branch_size)} (bvand  (bvxor ((_ rotate_left 7) dT_{i}) dT_{i}) doublebitsT_{i})))") # cond 2 thm 3
		print("(assert (=  lftT_",i+1,"  (bvxor (bvxor rgtT_",i," dT_",i,") (bvxor ((_ rotate_left 2) lftT_",i,") keyT_",i,"))))", sep = '') # compute resulting left diff
		print("(assert (=  zT_",i," (bvxor varibitsT_",i,"  doublebitsT_",i,")))", sep = '') #	z = varibits + doublebits




	# -----------------------------------------------  BOTTOM TRAIL --------------------------------------------

	# state differences, bottom trail in E1
	for i in range(NbrE0+NbrEm, NbrE0+NbrEm+NbrE1):
		print("(assert (=  rgtB_",i+1,"  lftB_",i," ))", sep = '') # copied branch   rgt i+1 = lft i
		print("(assert (=  varibitsB_",i,"  (bvor  ((_ rotate_left 8) lftB_",i,") ((_ rotate_left 1)lftB_",i,"))))", sep = '') # varibits computation
		print(f"(assert (=  doublebitsB_{i} (bvand (bvand (bvxor ((_ rotate_left 8) lftB_{i}) {minus_one(branch_size)}) ((_ rotate_left 1)lftB_{i})) ((_ rotate_left 15) lftB_{i}))))")#  doublebits computation
		print(f"(assert (=  {zero(branch_size)} (bvand  (bvxor varibitsB_{i} {minus_one(branch_size)})  dB_{i})))")	# cond 1 thm 3
		print(f"(assert (=  {zero(branch_size)} (bvand  (bvxor ((_ rotate_left 7) dB_{i}) dB_{i}) doublebitsB_{i})))") # cond 2 thm 3
		print("(assert (=  lftB_",i+1,"  (bvxor (bvxor rgtB_",i," dB_",i,") (bvxor ((_ rotate_left 2) lftB_",i,") keyB_",i,"))))", sep = '') # compute resulting left diff
		print("(assert (=  zB_",i," (bvxor varibitsB_",i,"  doublebitsB_",i,")))", sep = '') #	z = varibits + doublebits






	# -----------------------------------------------  MIDDLE PART --------------------------------------------

	for i in range(NbrE0+1):
		print(f"(assert (= {zero(branch_size)} u_lftT_{i}  ))")			# ok
		print(f"(assert (= {zero(branch_size)} u_rgtT_{i}  ))")

	for i in range(NbrE0+NbrEm,NbrE0+NbrEm+NbrE1+1):
		print(f"(assert (= {zero(branch_size)} u_lftB_{i}  ))")			# ok
		print(f"(assert (= {zero(branch_size)} u_rgtB_{i}  ))")



	# BCT verification
	for i in range(NbrE0,NbrE0+NbrEm):
		if not impossible:
			if not rx_d:
				# one line version (no j)
				print(f"(assert (= {minus_one(branch_size)} (bvor (bvand (bvor (bvand (bvnot ((_ rotate_left 8) u_lftT_{i}) ) (bvnot  ((_ rotate_left 8) lftT_{i}) )) (bvand (bvnot  ((_ rotate_left 1) u_rgtB_{i+1}) )  (bvnot ((_ rotate_left 1) rgtB_{i+1}) ) )) (bvor (bvand (bvnot ((_ rotate_left 1) u_lftT_{i})) (bvnot ((_ rotate_left 1) lftT_{i}))) (bvand (bvnot ((_ rotate_left 8) u_rgtB_{i+1}) )  (bvnot ((_ rotate_left 8) rgtB_{i+1}) ) )) ) (bvand (bvand (bvand (bvnot ((_ rotate_left 8) u_lftT_{i}) )   ((_ rotate_left 8) lftT_{i})) (bvand (bvnot  ((_ rotate_left 1) u_rgtB_{i+1}) )  ((_ rotate_left 1) rgtB_{i+1})) ) (bvand (bvand (bvnot ((_ rotate_left 1) u_lftT_{i}) )  ((_ rotate_left 1) lftT_{i})) (bvand (bvnot ((_ rotate_left 8) u_rgtB_{i+1}) )  ((_ rotate_left 8) rgtB_{i+1})) ) ) ) ) )")
			else:
				print(f"(assert (= {minus_one(branch_size)} (bvor (bvand (bvor (bvand (bvnot ((_ rotate_left 8) u_lftT_{i}) ) (bvnot  ((_ rotate_left 8) lftT_{i}) )) (bvand (bvnot  ((_ rotate_left {1+rotation_index}) u_rgtB_{i+1}) )  (bvnot ((_ rotate_left {1+rotation_index}) rgtB_{i+1}) ) )) (bvor (bvand (bvnot ((_ rotate_left 1) u_lftT_{i})) (bvnot ((_ rotate_left 1) lftT_{i}))) (bvand (bvnot ((_ rotate_left {8+rotation_index}) u_rgtB_{i+1}) )  (bvnot ((_ rotate_left {8+rotation_index}) rgtB_{i+1}) ) )) ) (bvand (bvand (bvand (bvnot ((_ rotate_left 8) u_lftT_{i}) )   ((_ rotate_left 8) lftT_{i})) (bvand (bvnot  ((_ rotate_left {1+rotation_index}) u_rgtB_{i+1}) )  ((_ rotate_left {1+rotation_index}) rgtB_{i+1})) ) (bvand (bvand (bvnot ((_ rotate_left 1) u_lftT_{i}) )  ((_ rotate_left 1) lftT_{i})) (bvand (bvnot ((_ rotate_left {8+rotation_index}) u_rgtB_{i+1}) )  ((_ rotate_left {8+rotation_index}) rgtB_{i+1})) ) ) ) ) )")
		else:
			print(f"(assert (= constraintmask_{i} (bvand (bvxor (bvand {shift(f'lftT_{i}',1)} {shift(f'rgtB_{i+1}',8)}) (bvand {shift(f'lftT_{i}',8)} {shift(f'rgtB_{i+1}',1)})) (bvnot (bvor (bvor (bvxor (bvand (bvor  {shift(f'lftT_{i}',1)}  {shift(f'u_lftT_{i}',1)})  (bvor  {shift(f'rgtB_{i+1}',8)}  {shift(f'u_rgtB_{i+1}',8)})) (bvand  {shift(f'lftT_{i}',1)}  {shift(f'rgtB_{i+1}',8)})) (bvxor (bvand (bvor  {shift(f'lftT_{i}',8)}  {shift(f'u_lftT_{i}',8)})  (bvor  {shift(f'rgtB_{i+1}',1)}  {shift(f'u_rgtB_{i+1}',1)})) (bvand  {shift(f'lftT_{i}',8)}  {shift(f'rgtB_{i+1}',1)}))) (bvor (bvor u_rgtT_{i} u_lftB_{i+1}) (bvand {shift(f'u_lftT_{i}',2)} {shift(f'u_rgtB_{i+1}',2)})) )) )))")

	# propagation in Em, top trail
	for i in range(NbrE0,NbrE0+NbrEm-1):		# for all the middle rounds
		print(f"(assert (= {zero(branch_size)} (bvand lftT_{i+1} u_lftT_{i+1})))") # unknown => difference = 0

		print("(assert (=  rgtT_",i+1,"  lftT_",i," ))", sep = '') 		# copied branch   difference
		print("(assert (=  u_rgtT_",i+1,"  u_lftT_",i," ))", sep = '') 	# copied branch   unknown status

		print("(assert (=  computableT_",i," (bvand (bvand (bvand (bvnot ((_ rotate_left 2) u_lftT_",i,")) (bvnot u_rgtT_",i,")) (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,")) (bvnot ((_ rotate_left 8) u_lftT_",i,")))) (bvand (bvnot ((_ rotate_left 1) lftT_",i,")) (bvnot ((_ rotate_left 8) lftT_",i,")) ) )))" , sep = '') # and key always known  changed

		print(f"(assert (= {minus_one(branch_size)} (bvor (bvnot PayT_{i}) (bvor {shift(f'lftT_{i}',1)} {shift(f'lftT_{i}',8)}  ))))") # Pay => active
		print(f"(assert (= doublebitsT_{i} (bvand (bvand PayT_{i} {shift(f'PayT_{i}',7)}) (bvnot {shift(f'lftT_{i}',8)}))))") # Double if 2 pays and an inactive bit
		print(f"(assert (= {zero(branch_size)} (bvand (bvand PayT_{i} {shift(f'PayT_{i}',7)}) {shift(f'u_lftT_{i}',8)})))") # Two pays => known bit

		print("(assert (=  u_lftT_",i+1,"  (bvand (bvnot computableT_",i,") (bvnot  PayT_",i," ))))", sep = '') # ok

		print("(assert (= computedValueT_",i," (bvxor (bvxor ((_ rotate_left 2) lftT_",i,") keyT_",i," ) rgtT_",i,")))", sep = '')	# if computable, this is what is the linear term changed

		print(f"(assert (= (bvand computableT_{i} lftT_{i+1}) (bvand computableT_{i} computedValueT_{i} )) )") # Computable => result equals computed value
		print(f"(assert (= {zero(branch_size)} (bvand doublebitsT_{i} (bvxor (bvxor (bvxor rgtT_{i} {shift(f'lftT_{i}',2)}) (bvxor keyT_{i} lftT_{i+1}) ) (bvxor (bvxor {shift(f'rgtT_{i}',7)} {shift(f'lftT_{i}',9)}) (bvxor {shift(f'keyT_{i}',7)} {shift(f'lftT_{i+1}',7)} ))))))") # Double bits => equal outputs of the ands




	# propagation in Em, bottom trail
	for i in range(NbrE0+1,NbrE0+NbrEm):		# for all the middle rounds
		print(f"(assert (= {zero(branch_size)} (bvand rgtB_{i} u_rgtB_{i})))") # unknown => difference = 0


		print("(assert (=  rgtB_",i+1,"  lftB_",i," ))", sep = '') 		# copied branch   difference           v
		print("(assert (=  u_rgtB_",i+1,"  u_lftB_",i," ))", sep = '') 	# copied branch   unknown status       v

		print("(assert (= computableB_",i," (bvand (bvand (bvand (bvnot u_lftB_",i+1,") (bvnot ((_ rotate_left 2) u_lftB_",i,") )) (bvand (bvnot ((_ rotate_left 1) u_lftB_",i,")) (bvnot ((_ rotate_left 8) u_lftB_",i,")))) (bvand (bvnot ((_ rotate_left 1) lftB_",i,")) (bvnot ((_ rotate_left 8) lftB_",i,")) )))) " , sep = '') # changed

		print(f"(assert (= {minus_one(branch_size)} (bvor (bvnot PayB_{i}) (bvor {shift(f'lftB_{i}',1)} {shift(f'lftB_{i}',8)}  ))))") # Pay => active
		print(f"(assert (= doublebitsB_{i} (bvand (bvand PayB_{i} {shift(f'PayB_{i}',7)}) (bvnot {shift(f'lftB_{i}',8)}))))") # Double if 2 pays and an inactive bit
		print(f"(assert (= {zero(branch_size)} (bvand (bvand PayB_{i} {shift(f'PayB_{i}',7)}) {shift(f'u_lftB_{i}',8)})))") # Two pays => known bit

		print("(assert (=  u_rgtB_",i,"  (bvand (bvnot computableB_",i,") (bvnot PayB_",i," ))))", sep = '')

		print("(assert (= computedValueB_",i," (bvxor (bvxor lftB_",i+1," keyB_",i," ) ((_ rotate_left 2) lftB_",i,") )))", sep = '')

		print(f"(assert (= (bvand computableB_{i} rgtB_{i}) (bvand computableB_{i} computedValueB_{i} )) )") # Computable => result equals computed value
		print(f"(assert (= {zero(branch_size)} (bvand doublebitsB_{i} (bvxor (bvxor (bvxor rgtB_{i} {shift(f'lftB_{i}',2)}) (bvxor keyB_{i} lftB_{i+1}) ) (bvxor (bvxor {shift(f'rgtB_{i}',7)} {shift(f'lftB_{i}',9)}) (bvxor {shift(f'keyB_{i}',7)} {shift(f'lftB_{i+1}',7)} ) )))))") # Double bits => equal outputs of the ands


	# -----------------------------------------------  OBJECTIVE  --------------------------------------------


	for i in range(NbrE0):											# E0
		print("(assert (= wrT_",i," (w_H zT_",i,")))", sep = '')  	# probability in each round = hamming weight of z_
	for i in range(NbrE0, NbrE0+NbrEm-1):							# Em
		print("(assert (= wrT_",i," (bvadd (w_H PayT_",i,") (bvneg (w_H doublebitsT_",i,") ))))", sep = '') 	# probability in each round = PayT


	for i in range(NbrE0+1, NbrE0+NbrEm):							# Em
		print("(assert (= wrB_",i," (bvadd (w_H PayB_",i,") (bvneg (w_H doublebitsB_",i,") ))))", sep = '') 	# probability in each round = PayT
	for i in range(NbrE0+NbrEm, NbrE0+NbrEm+NbrE1):					# E1
		print("(assert (= wrB_",i," (w_H zB_",i,")))", sep = '')  	# probability in each round = hamming weight of z_



	# sum all wrT_ to get final proba, has to be equal to bound_plain, which is a parameter

	print("(assert (=  #b",OBJ," ", sep = '',end='')
	for i in range(NbrE0):
		print("(bvadd ((_ rotate_left 1) wrT_",i,") ", sep = '',end='')
	for i in range(NbrE0, NbrE0+NbrEm-1):
		print("(bvadd  wrT_",i," ", sep = '', end='')
	for i in range(NbrE0+1, NbrE0+NbrEm):
		print("(bvadd  wrB_",i," ", sep = '',end='')
	for i in range(NbrE0+NbrEm, NbrE0+NbrEm+NbrE1-1):
		print("(bvadd ((_ rotate_left 1) wrB_",i,") ", sep = '',end='')
	print("((_ rotate_left 1) wrB_", NbrE0+NbrEm+NbrE1-1," ", sep = '',end='')
	for i in range(NbrE0+NbrEm-1):
		print(")",end='')
	for i in range(NbrE0+1,NbrE0+NbrEm+NbrE1):
		print(")",end='')
	print(" ))", sep = '')



	# -----------------------------------------------  RESOLUTION  --------------------------------------------


	# solve
	print("(check-sat)")

	# print solution
	# 									keys
	for i in range(NbrE0+NbrEm+NbrE1):
		print("(get-value ( kT_",i,"))", sep = '')
	for i in range(NbrE0+NbrEm+NbrE1):
		print("(get-value ( kB_",i,"))", sep = '')
	# 									TOP TRAIL
	for i in range(NbrE0+NbrEm):
		print("(get-value ( lftT_",i,"))", sep = '')
		print("(get-value ( rgtT_",i,"))", sep = '')
		print("(get-value ( u_lftT_",i,"))", sep = '')
		print("(get-value ( u_rgtT_",i,"))", sep = '')

	#for i in range(NbrE0+NbrEm-1):
	#	print("(get-value ( keyT_",i,"))", sep = '')
	#	print("(get-value ( dT_",i,"))", sep = '')
	#	print("(get-value ( varibitsT_",i,"))", sep = '')
	#	print("(get-value ( doublebitsT_",i,"))", sep = '')
	#	print("(get-value ( zT_",i,"))", sep = '')
	#	print("(get-value ( wrT_",i,"))", sep = '')


	# 									BOTTOM TRAIL
	for i in range((NbrE0 + 1), (NbrE0 + NbrEm + NbrE1+1)):
		print("(get-value ( lftB_",i,"))", sep = '')
		print("(get-value ( rgtB_",i,"))", sep = '')
		print("(get-value ( u_lftB_",i,"))", sep = '')
		print("(get-value ( u_rgtB_",i,"))", sep = '')
	#for i in range((NbrE0 + 1), (NbrE0 + NbrEm + NbrE1)):
	#	print("(get-value ( keyB_",i,"))", sep = '')
	#	print("(get-value ( dB_",i,"))", sep = '')
	#	print("(get-value ( varibitsB_",i,"))", sep = '')
	#	print("(get-value ( doublebitsB_",i,"))", sep = '')
	#	print("(get-value ( zB_",i,"))", sep = '')
	#	print("(get-value ( wrB_",i,"))", sep = '')



	for i in range(NbrEm-1):
		print("(get-value ( PayT_",i+NbrE0,"))", sep = '')
		print("(get-value ( PayB_",i+NbrE0+1,"))", sep = '')




	for i in range(4):
		print("(get-value ( kT_",i,"))", sep = '')

	for i in range(4):
		print("(get-value ( kB_",i+NbrE0+NbrEm+NbrE1-4,"))", sep = '')

	print("(get-value ( lftT_",0,"))", sep = '')
	print("(get-value ( rgtT_",0,"))", sep = '')

	print("(get-value ( lftB_",NbrE0+NbrEm+NbrE1,"))", sep = '')
	print("(get-value ( rgtB_",NbrE0+NbrEm+NbrE1,"))", sep = '')

	if impossible :
		for i in range(NbrE0,NbrE0+NbrEm):
			print(f"(get-value ( constraintmask_{i} ))")

	print("(exit)")


if __name__ == '__main__':
	main()
