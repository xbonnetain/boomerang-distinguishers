#
# SMT model generator for Simon32 boomerangs
#
# Authors:
# Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
#
# Built upon the SMT model for Simon32 rotational-xor differentials from
# Improved Rotational-XOR Cryptanalysis of Simon-like Block Ciphers
# by Jinyu Lu, Yunwen Liu, Tomer Ashur, Bing Sun and Chao Li.
#



import sys


def shift(s,i):
	return f"((_ rotate_left {i}) {s})"

def usage():
	print("""
Usage: python simonSMTpython.py tag start_round E0_rounds Em_rounds E1_round target_probability

	tag:
		rk: related-key boomerang
		rot: rotational-xor related-key boomerang
		rxd: rotational-xor-differential related-key boomerang

	Generate SMT model for boomerang with probability 2^{-target_probability}
""",file=sys.stderr)
	exit()

def main():
	name = sys.argv[0]
	if len(sys.argv)!=7:
		usage()
	tag = sys.argv[1]
	if tag == "rxd":
		rk_d = True
		rotational = True
		s = "RXD"
	elif tag == "rk":
		s = "RK"
		rotational = False
		rk_d = False
	elif tag == "rot":
		s = "Rotational-xor"
		rotational = True
		rk_d = False
	else:
		usage()

	start_round = int(sys.argv[2])
	nE0 = int(sys.argv[3])
	nEm = int(sys.argv[4])
	nE1 = int(sys.argv[5])
	obj = int(sys.argv[6])
	print_query(start_round, nE0, nEm, nE1,obj,check_instanciable=True,rk_d=rk_d, rotational=rotational)
	print(f"\nGenerated {s} constraints for {nE0+nEm+nE1} rounds (cut {nE0}+{nEm}+{nE1}) objective {obj}",file=sys.stderr)


# startingIndex: round at which starts the distinguisher
# NbrE0: number of rounds in E0
# NbrEm: number of middle round conditions to be checked
# NbrE1: number of rounds in E1
# obj: aimed distinguisher probability
# check_instanciable: check that there exists one quartet of messages and keys that follow the characteristic
# rk_d: for rxd
# rotational: for rot and rxd
def print_query(startingIndex, NbrE0, NbrEm, NbrE1, obj,check_instanciable=False,rk_d=False, rotational=True):
	# objective probability
	OBJ = bin(obj)[2:].zfill(16)

	# constant for key schedule: z0 for Simon 32
	z0_full = [1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0]

	z0 = z0_full[startingIndex:]

	# -------------------------------- parameters for the solver  --------------------------------
	print("(set-logic QF_ABV)")
	print("(set-info :smt-lib-version 2.5)")
	print("(set-option :produce-models true)\n")

	# --------------------------------  creating variables  --------------------------------------

	# definition of the Hamming weight function
	print(" (define-fun w_H0 ((x (_ BitVec 16))) (_ BitVec 16) ")
	print("       (bvadd (bvand x #x5555 ) ")
	print("              (bvand (bvlshr x #x0001) #x5555 ))) ")
	print(" (define-fun w_H1 ((x (_ BitVec 16))) (_ BitVec 16) ")
	print("       (bvadd (bvand x #x3333 ) ")
	print("              (bvand (bvlshr x #x0002) #x3333 ))) ")
	print(" (define-fun w_H2 ((x (_ BitVec 16))) (_ BitVec 16) ")
	print("       (bvadd (bvand x #x0f0f ) ")
	print("              (bvand (bvlshr x #x0004) #x0f0f))) ")
	print(" (define-fun w_H3 ((x (_ BitVec 16))) (_ BitVec 16) ")
	print("       (bvadd (bvand x #x00ff ) ")
	print("              (bvand (bvlshr x #x0008) #x00ff ))) ")
	print(" (define-fun w_H ((x (_ BitVec 16))) (_ BitVec 16) (w_H3 (w_H2 (w_H1 (w_H0 x))))) ")



	for i in range(NbrE0+NbrEm+NbrE1):										#  TOP and BOTTOM key
		print("(declare-fun kT_",i," () (_ BitVec 16))", sep = '')			#  for key schedule
		print("(declare-fun kB_",i," () (_ BitVec 16))", sep = '')			#  for key schedule


	for i in range(NbrE0+NbrEm+NbrE1-4):
		print("(declare-fun c_",i," () (_ BitVec 16))", sep = '') 			# constant for key schedule
	
	
	#									TOP TRAIL

	for i in range(NbrE0+NbrEm):										#				indices (0) to (NbrE0 + NbrEm -1 )
		print("(declare-fun lftT_",i," () (_ BitVec 16))", sep = '')	# lft, diff
		print("(declare-fun rgtT_",i," () (_ BitVec 16))", sep = '')	# rgt, diff

		print("(declare-fun u_lftT_",i," () (_ BitVec 16))", sep = '')	# known lft, diff
		print("(declare-fun u_rgtT_",i," () (_ BitVec 16))", sep = '')	# known rgt, diff

	for i in range(NbrE0+NbrEm-1):
		print("(declare-fun keyT_",i," () (_ BitVec 16))", sep = '')	# key, diff
		print("(declare-fun wrT_",i," () (_ BitVec 16))", sep = '')		#  HW of z, ie proba of 1 round

	for i in range(NbrE0):
		print("(declare-fun dT_",i," () (_ BitVec 16))", sep = '')			# = \gamma from https://ia.cr/2015/145
		print("(declare-fun varibitsT_",i," () (_ BitVec 16))", sep = '')	#  varibits notation from https://ia.cr/2015/145
		print("(declare-fun doublebitsT_",i," () (_ BitVec 16))", sep = '')	#  doublebits notation from https://ia.cr/2015/145
		print("(declare-fun zT_",i," () (_ BitVec 16))", sep = '')			#  z = varibits + doublebits


	#									BOTTOM TRAIL

	for i in range(NbrEm+NbrE1):												# BOTTOM TRAIL = Em + E1   	 indices (NbrE0 + 1) to (NbrE0 + NbrEm + NbrE1 )
		print("(declare-fun lftB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')	# lft, diff
		print("(declare-fun rgtB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')	# rgt, diff

		print("(declare-fun u_lftB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')	# known lft, diff
		print("(declare-fun u_rgtB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')	# known rgt, diff


	for i in range(NbrEm+NbrE1-1):
		print("(declare-fun keyB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')	# key, diff
		print("(declare-fun wrB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')		#  HW of z, ie proba of 1 round

	for i in range(NbrE1):
		print("(declare-fun dB_"			,i+NbrE0+NbrEm," () (_ BitVec 16))", sep = '')	# = \gamma from https://ia.cr/2015/145
		print("(declare-fun varibitsB_"		,i+NbrE0+NbrEm," () (_ BitVec 16))", sep = '')	#  varibits notation from https://ia.cr/2015/145
		print("(declare-fun doublebitsB_"	,i+NbrE0+NbrEm," () (_ BitVec 16))", sep = '')	#  doublebits notation from https://ia.cr/2015/145
		print("(declare-fun zB_"			,i+NbrE0+NbrEm," () (_ BitVec 16))", sep = '')	#  z = varibits + doublebits


	if check_instanciable:
		#normal simon Round
		print(f"(define-fun simon (( l (_ BitVec 16)) (r (_ BitVec 16)) (k (_ BitVec 16))) (_ BitVec 16) (bvxor (bvxor (bvand {shift('l',8)} {shift('l',1)}) {shift('l',2)}) (bvxor r k)))")


		for i in range(NbrE0+NbrEm+NbrE1+1):
			print("(declare-fun vl0_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vl1_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vl2_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vl3_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vr0_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vr1_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vr2_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun vr3_",i," () (_ BitVec 16))", sep = '')

		for i in range(NbrE0+NbrEm+NbrE1):
			print("(declare-fun k0_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun k1_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun k2_",i," () (_ BitVec 16))", sep = '')
			print("(declare-fun k3_",i," () (_ BitVec 16))", sep = '')
			print(f"(assert (= vr0_{i+1} vl0_{i}))")
			print(f"(assert (= vr1_{i+1} vl1_{i}))")
			print(f"(assert (= vr2_{i+1} vl2_{i}))")
			print(f"(assert (= vr3_{i+1} vl3_{i}))")
			print(f"(assert (= vl0_{i+1} (simon vl0_{i} vr0_{i} k0_{i})))")
			print(f"(assert (= vl1_{i+1} (simon vl1_{i} vr1_{i} k1_{i})))")
			print(f"(assert (= vl2_{i+1} (simon vl2_{i} vr2_{i} k2_{i})))")
			print(f"(assert (= vl3_{i+1} (simon vl3_{i} vr3_{i} k3_{i})))")
			print(f"(assert (= k1_{i} (bvxor kT_{i} {shift(f'k0_{i}',1)})))")
			print(f"(assert (= k3_{i} (bvxor kT_{i} {shift(f'k2_{i}',1)})))")
			print(f"(assert (= k3_{i} (bvxor kB_{i} {shift(f'k0_{i}',1)})))")

		for i in range(NbrE0+NbrEm):
			print(f"(assert (= (bvor u_lftT_{i} vl1_{i}) (bvor u_lftT_{i} (bvxor {shift(f'vl0_{i}',1)} lftT_{i}))))")
			print(f"(assert (= (bvor u_lftT_{i} vl3_{i}) (bvor u_lftT_{i} (bvxor {shift(f'vl2_{i}',1)} lftT_{i}))))")
			print(f"(assert (= (bvor u_rgtT_{i} vr1_{i}) (bvor u_rgtT_{i} (bvxor {shift(f'vr0_{i}',1)} rgtT_{i}))))")
			print(f"(assert (= (bvor u_rgtT_{i} vr3_{i}) (bvor u_rgtT_{i} (bvxor {shift(f'vr2_{i}',1)} rgtT_{i}))))")
		for i in range(NbrE0+1,NbrE0+NbrEm+NbrE1+1):
			print(f"(assert (= (bvor u_lftB_{i} vl3_{i}) (bvor u_lftB_{i} (bvxor {shift(f'vl0_{i}',1)} lftB_{i}))))")
			print(f"(assert (= (bvor u_lftB_{i} vl1_{i}) (bvor u_lftB_{i} (bvxor {shift(f'vl2_{i}',1)} lftB_{i}))))")
			print(f"(assert (= (bvor u_rgtB_{i} vr3_{i}) (bvor u_rgtB_{i} (bvxor {shift(f'vr0_{i}',1)} rgtB_{i}))))")
			print(f"(assert (= (bvor u_rgtB_{i} vr1_{i}) (bvor u_rgtB_{i} (bvxor {shift(f'vr2_{i}',1)} rgtB_{i}))))")


	#									MIDDLE TRAIL

	for i in range(NbrEm-1):

		print("(declare-fun PayT_",i+NbrE0," () (_ BitVec 16))", sep = '')
		print("(declare-fun PayB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')

		print("(declare-fun computableT_",i+NbrE0," () (_ BitVec 16))", sep = '')
		print("(declare-fun computableB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')

		print("(declare-fun computedValueT_",i+NbrE0," () (_ BitVec 16))", sep = '')
		print("(declare-fun computedValueB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')

		print("(declare-fun doublebitsT_",i+NbrE0," () (_ BitVec 16))", sep = '')
		print("(declare-fun doublebitsB_",i+NbrE0+1," () (_ BitVec 16))", sep = '')



	if not rotational:
		print(f"(assert (or (or (not (= lftT_{0} #x0000)) (not (= rgtT_{0} #x0000))) (or (or (not (= #x0000 kT_{0})) (not (= #x0000 kT_{1}))) (or (not (= #x0000 kT_{2})) (not (= #x0000 kT_{3}))))))")
		print(f"(assert (or (or (not (= lftB_{NbrEm+NbrE1} #x0000)) (not (= rgtB_{NbrEm+NbrE1} #x0000))) (or (or (not (= #x0000 kB_{0})) (not (= #x0000 kB_{1}))) (or (not (= #x0000 kB_{2})) (not (= #x0000 kB_{3}))))))")

	if rk_d :
		print(f"(assert (or (not (= lftB_{NbrE0+NbrEm+NbrE1} #x0000)) (not (= rgtB_{NbrE0+NbrEm+NbrE1} #x0000))))")


	# -----------------------------------------------  KEY SCHEDULE --------------------------------------------

	# key schedule for the top and bottom keys, for all the rounds
	# gives the kT and kB
	for i in range(NbrE0+NbrEm+NbrE1-4):
		if rotational:
			if (z0[i] == 1):
				print("(assert (= c_",i," #xfffd))", sep = '') # cst = fffd if bit = 1
			else :
				print("(assert (= c_",i," #xfffc))", sep = '') # cst = fffc if bit = 0
		else :
				print("(assert (= c_",i," #x0000))", sep = '') # no cst if no rotational

		print("(assert (= kT_",i+4,"  (bvxor ((_ rotate_right 1)(bvxor ((_ rotate_right 3) kT_",i+3,") kT_",i+1,"))(bvxor (bvxor kT_",i,"  (bvxor ((_ rotate_left 1) c_",i,") c_",i,")) (bvxor ((_ rotate_right 3) kT_",i+3,") kT_",i+1,")))))", sep = '')
		if not rk_d:
			# k_i+4= (k_i+3 >>> 4) + (k_i+1 >>> 1)  + ki +  (k_i+3>>>3) + (k_i+1) +  c_i <<< 1 + c_i
			print("(assert (= kB_",i+4,"  (bvxor ((_ rotate_right 1)(bvxor ((_ rotate_right 3) kB_",i+3,") kB_",i+1,"))(bvxor (bvxor kB_",i,"  (bvxor ((_ rotate_left 1) c_",i,") c_",i,")) (bvxor ((_ rotate_right 3) kB_",i+3,") kB_",i+1,")))))", sep = '')
	for i in range(NbrE0+NbrEm+NbrE1):
		if rk_d:
			print(f"(assert ( = #x0000 kB_{i}))")


	for i in range(NbrE0+NbrEm-1):
		print("(assert (=  keyT_",i,"  kT_",i,"))", sep = '')
	for i in range(NbrEm+NbrE1-1):
		print("(assert (=  keyB_",i+NbrE0+1,"  kB_",i+NbrE0+1,"))", sep = '')

	# -----------------------------------------------  TOP TRAIL --------------------------------------------

	# state differences, top trail in E0
	for i in range(NbrE0):
		print("(assert (=  rgtT_",i+1,"  lftT_",i," ))", sep = '') # copied branch   rgt i+1 = lft i
		print("(assert (=  varibitsT_",i,"  (bvor  ((_ rotate_left 8) lftT_",i,") ((_ rotate_left 1)lftT_",i,"))))", sep = '') # varibits computation
		print("(assert (=  doublebitsT_",i," (bvand (bvand (bvxor ((_ rotate_left 8) lftT_",i,") #xffff) ((_ rotate_left 1)lftT_",i,")) ((_ rotate_left 15) lftT_",i,"))))", sep = '')#  doublebits computation
		print("(assert (=  #x0000 (bvand  (bvxor varibitsT_",i," #xffff)  dT_",i,")))", sep = '')	# cond 1 thm 3
		print("(assert (=  #x0000 (bvand  (bvxor ((_ rotate_left 7) dT_",i,") dT_",i,") doublebitsT_",i,")))", sep = '') # cond 2 thm 3
		print("(assert (=  lftT_",i+1,"  (bvxor (bvxor rgtT_",i," dT_",i,") (bvxor ((_ rotate_left 2) lftT_",i,") keyT_",i,"))))", sep = '') # compute resulting left diff
		print("(assert (=  zT_",i," (bvxor varibitsT_",i,"  doublebitsT_",i,")))", sep = '') #	z = varibits + doublebits




	# -----------------------------------------------  BOTTOM TRAIL --------------------------------------------

	# state differences, bottom trail in E1
	for i in range(NbrE0+NbrEm, NbrE0+NbrEm+NbrE1):
		print("(assert (=  rgtB_",i+1,"  lftB_",i," ))", sep = '') # copied branch   rgt i+1 = lft i
		print("(assert (=  varibitsB_",i,"  (bvor  ((_ rotate_left 8) lftB_",i,") ((_ rotate_left 1)lftB_",i,"))))", sep = '') # varibits computation
		print("(assert (=  doublebitsB_",i," (bvand (bvand (bvxor ((_ rotate_left 8) lftB_",i,") #xffff) ((_ rotate_left 1)lftB_",i,")) ((_ rotate_left 15) lftB_",i,"))))", sep = '')#  doublebits computation
		print("(assert (=  #x0000 (bvand  (bvxor varibitsB_",i," #xffff)  dB_",i,")))", sep = '')	# cond 1 thm 3
		print("(assert (=  #x0000 (bvand  (bvxor ((_ rotate_left 7) dB_",i,") dB_",i,") doublebitsB_",i,")))", sep = '') # cond 2 thm 3
		print("(assert (=  lftB_",i+1,"  (bvxor (bvxor rgtB_",i," dB_",i,") (bvxor ((_ rotate_left 2) lftB_",i,") keyB_",i,"))))", sep = '') # compute resulting left diff
		print("(assert (=  zB_",i," (bvxor varibitsB_",i,"  doublebitsB_",i,")))", sep = '') #	z = varibits + doublebits







	# -----------------------------------------------  MIDDLE PART --------------------------------------------

	for i in range(NbrE0+1):
		print("(assert (= #b0000000000000000 u_lftT_",i,"  ))", sep = '')			
		print("(assert (= #b0000000000000000 u_rgtT_",i,"  ))", sep = '')

	for i in range(NbrE0+NbrEm,NbrE0+NbrEm+NbrE1+1):
		print("(assert (= #b0000000000000000 u_lftB_",i,"  ))", sep = '')			
		print("(assert (= #b0000000000000000 u_rgtB_",i,"  ))", sep = '')




	# BCT verification
	for i in range(NbrE0,NbrE0+NbrEm):
		if not rk_d or not rotational:
			print("(assert (= #xffff (bvor (bvand (bvor (bvand (bvnot ((_ rotate_left 8) u_lftT_",i,") ) (bvnot  ((_ rotate_left 8) lftT_",i,") )) (bvand (bvnot  ((_ rotate_left 1) u_rgtB_",i+1,") )  (bvnot ((_ rotate_left 1) rgtB_",i+1,") ) )) (bvor (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,")) (bvnot ((_ rotate_left 1) lftT_",i,"))) (bvand (bvnot ((_ rotate_left 8) u_rgtB_",i+1,") )  (bvnot ((_ rotate_left 8) rgtB_",i+1,") ) )) ) (bvand (bvand (bvand (bvnot ((_ rotate_left 8) u_lftT_",i,") )   ((_ rotate_left 8) lftT_",i,")) (bvand (bvnot  ((_ rotate_left 1) u_rgtB_",i+1,") )  ((_ rotate_left 1) rgtB_",i+1,")) ) (bvand (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,") )  ((_ rotate_left 1) lftT_",i,")) (bvand (bvnot ((_ rotate_left 8) u_rgtB_",i+1,") )  ((_ rotate_left 8) rgtB_",i+1,")) ) ) ) ) )", sep = '')
		else:
			print("(assert (= #xffff (bvor (bvand (bvor (bvand (bvnot ((_ rotate_left 8) u_lftT_",i,") ) (bvnot  ((_ rotate_left 8) lftT_",i,") )) (bvand (bvnot  ((_ rotate_left 2) u_rgtB_",i+1,") )  (bvnot ((_ rotate_left 2) rgtB_",i+1,") ) )) (bvor (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,")) (bvnot ((_ rotate_left 1) lftT_",i,"))) (bvand (bvnot ((_ rotate_left 9) u_rgtB_",i+1,") )  (bvnot ((_ rotate_left 9) rgtB_",i+1,") ) )) ) (bvand (bvand (bvand (bvnot ((_ rotate_left 8) u_lftT_",i,") )   ((_ rotate_left 8) lftT_",i,")) (bvand (bvnot  ((_ rotate_left 2) u_rgtB_",i+1,") )  ((_ rotate_left 2) rgtB_",i+1,")) ) (bvand (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,") )  ((_ rotate_left 1) lftT_",i,")) (bvand (bvnot ((_ rotate_left 9) u_rgtB_",i+1,") )  ((_ rotate_left 9) rgtB_",i+1,")) ) ) ) ) )", sep = '')


	# propagation in Em, top trail
	for i in range(NbrE0,NbrE0+NbrEm-1):		# for all the middle rounds
		print(f"(assert (= #x0000 (bvand lftT_{i} u_lftT_{i})))") # unknown => difference = 0

		print("(assert (=  rgtT_",i+1,"  lftT_",i," ))", sep = '') 		# copied branch   difference
		print("(assert (=  u_rgtT_",i+1,"  u_lftT_",i," ))", sep = '') 	# copied branch   unknown status

		print("(assert (=  computableT_",i," (bvand (bvand (bvand (bvnot ((_ rotate_left 2) u_lftT_",i,")) (bvnot u_rgtT_",i,")) (bvand (bvnot ((_ rotate_left 1) u_lftT_",i,")) (bvnot ((_ rotate_left 8) u_lftT_",i,")))) (bvand (bvnot ((_ rotate_left 1) lftT_",i,")) (bvnot ((_ rotate_left 8) lftT_",i,")) ) )))" , sep = '') # and key always known

		print(f"(assert (= #xffff (bvor (bvnot PayT_{i}) (bvor {shift(f'lftT_{i}',1)} {shift(f'lftT_{i}',8)}  ))))") # Pay => active
		print(f"(assert (= doublebitsT_{i} (bvand (bvand PayT_{i} {shift(f'PayT_{i}',7)}) (bvnot {shift(f'lftT_{i}',8)}))))") # Double if 2 pays and an inactive bit
		print(f"(assert (= #x0000 (bvand (bvand PayT_{i} {shift(f'PayT_{i}',7)}) {shift(f'u_lftT_{i}',8)})))") # Two pays => known bit

		print("(assert (=  u_lftT_",i+1,"  (bvand (bvnot computableT_",i,") (bvnot  PayT_",i," ))))", sep = '')

		print("(assert (= computedValueT_",i," (bvxor (bvxor ((_ rotate_left 2) lftT_",i,") keyT_",i," ) rgtT_",i,")))", sep = '')	# if computable, this is what is the linear term

		print(f"(assert (= (bvand computableT_{i} lftT_{i+1}) (bvand computableT_{i} computedValueT_{i} )) )") # Computable => result equals computed value
		print(f"(assert (= #x0000 (bvand doublebitsT_{i} (bvxor (bvxor (bvxor rgtT_{i} {shift(f'lftT_{i}',2)}) (bvxor keyT_{i} lftT_{i+1}) ) (bvxor (bvxor {shift(f'rgtT_{i}',7)} {shift(f'lftT_{i}',9)}) (bvxor {shift(f'keyT_{i}',7)} {shift(f'lftT_{i+1}',7)} ))))))") # Double bits => equal outputs of the ands




	# propagation in Em, bottom trail
	for i in range(NbrE0+1,NbrE0+NbrEm):		# for all the middle rounds
		print(f"(assert (= #x0000 (bvand lftB_{i} u_lftB_{i})))") # unknown => difference = 0


		print("(assert (=  rgtB_",i+1,"  lftB_",i," ))", sep = '') 		# copied branch   difference           
		print("(assert (=  u_rgtB_",i+1,"  u_lftB_",i," ))", sep = '') 	# copied branch   unknown status       

		print("(assert (= computableB_",i," (bvand (bvand (bvand (bvnot u_lftB_",i+1,") (bvnot ((_ rotate_left 2) u_lftB_",i,") )) (bvand (bvnot ((_ rotate_left 1) u_lftB_",i,")) (bvnot ((_ rotate_left 8) u_lftB_",i,")))) (bvand (bvnot ((_ rotate_left 1) lftB_",i,")) (bvnot ((_ rotate_left 8) lftB_",i,")) )))) " , sep = '') 

		print(f"(assert (= #xffff (bvor (bvnot PayB_{i}) (bvor {shift(f'lftB_{i}',1)} {shift(f'lftB_{i}',8)}  ))))") # Pay => active
		print(f"(assert (= doublebitsB_{i} (bvand (bvand PayB_{i} {shift(f'PayB_{i}',7)}) (bvnot {shift(f'lftB_{i}',8)}))))") # Double if 2 pays and an inactive bit
		print(f"(assert (= #x0000 (bvand (bvand PayB_{i} {shift(f'PayB_{i}',7)}) {shift(f'u_lftB_{i}',8)})))") # Two pays => known bit

		print("(assert (=  u_rgtB_",i,"  (bvand (bvnot computableB_",i,") (bvnot PayB_",i," ))))", sep = '')

		print("(assert (= computedValueB_",i," (bvxor (bvxor lftB_",i+1," keyB_",i," ) ((_ rotate_left 2) lftB_",i,") )))", sep = '')

		print(f"(assert (= (bvand computableB_{i} rgtB_{i}) (bvand computableB_{i} computedValueB_{i} )) )") # Computable => result equals computed value
		print(f"(assert (= #x0000 (bvand doublebitsB_{i} (bvxor (bvxor (bvxor rgtB_{i} {shift(f'lftB_{i}',2)}) (bvxor keyB_{i} lftB_{i+1}) ) (bvxor (bvxor {shift(f'rgtB_{i}',7)} {shift(f'lftB_{i}',9)}) (bvxor {shift(f'keyB_{i}',7)} {shift(f'lftB_{i+1}',7)} ) )))))") # Double bits => equal outputs of the ands



	# -----------------------------------------------  OBJECTIVE  --------------------------------------------


	for i in range(NbrE0):											# E0
		print("(assert (= wrT_",i," (w_H zT_",i,")))", sep = '')  	# probability in each round = hamming weight of z_
	for i in range(NbrE0, NbrE0+NbrEm-1):							# Em
		print("(assert (= wrT_",i," (bvadd (w_H PayT_",i,") (bvneg (w_H doublebitsT_",i,") ))))", sep = '') 	# probability in each round = PayT


	for i in range(NbrE0+1, NbrE0+NbrEm):							# Em
		print("(assert (= wrB_",i," (bvadd (w_H PayB_",i,") (bvneg (w_H doublebitsB_",i,") ))))", sep = '') 	# probability in each round = PayT
	for i in range(NbrE0+NbrEm, NbrE0+NbrEm+NbrE1):					# E1
		print("(assert (= wrB_",i," (w_H zB_",i,")))", sep = '')  	# probability in each round = hamming weight of z_



	# sum all wrT_ to get final proba, has to be equal to the objective

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






	print("(exit)")

		

if __name__ == '__main__':
	main()
