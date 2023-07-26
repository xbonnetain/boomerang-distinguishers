#
# SMT Model generator for KATAN32 boomerangs
#
# Authors:
# Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria
#

import sys

def header(f):
	print("(set-logic QF_ABV)",file=f)
	print("(set-info :smt-lib-version 2.5)",file=f)
	print("(set-option :produce-models true)\n",file=f)

def i2v(i,l):
	# Yup.
	return "#b{:0{l}b}".format(i,l=l)

def bit(v,b):
	return f"((_ extract {b} {b}) {v})"

IR = [   1,1,1,1,1,1,1,0,0,0,
	1,1,0,1,0,1,0,1,0,1,  1,1,1,0,1,1,0,0,1,1,  0,0,1,0,1,0,0,1,0,0,  0,1,0,0,0,1,1,0,0,0,  1,1,1,1,0,0,0,0,1,0,  0,0,0,1,0,1,0,0,0,0,
	0,1,1,1,1,1,0,0,1,1,  1,1,1,1,0,1,0,1,0,0,  0,1,0,1,0,1,0,0,1,1,  0,0,0,0,1,1,0,0,1,1,  1,0,1,1,1,1,1,0,1,1,  1,0,1,0,0,1,0,1,0,1,
	1,0,1,0,0,1,1,1,0,0,  1,1,0,1,1,0,0,0,1,0,  1,1,1,0,1,1,0,1,1,1,  1,0,0,1,0,1,1,0,1,1,  0,1,0,1,1,1,0,0,1,0,  0,1,0,0,1,1,0,1,0,0,
	0,1,1,1,0,0,0,1,0,0,  1,1,1,1,0,1,0,0,0,0,  1,1,1,0,1,0,1,1,0,0,  0,0,0,1,0,1,1,0,0,1,  0,0,0,0,0,0,1,1,0,1,  1,1,0,0,0,0,0,0,0,1,
	0,0,1,0]

def force_bit(var,b,f):
		if b:
			print(f"(assert (= {var} #b1))",file=f)
		else:
			print(f"(assert (= {var} #b0))",file=f)

def core(nE0,nEm,nE1,f, sk=False):

	fwd_rds = nE0+nEm
	bwd_rds = nEm+nE1
	rds = nE0+nEm+nE1

	# creating variables : x, y (L1, L2)
	for i in range(fwd_rds):
		print(f"(declare-fun xT_{i} () (_ BitVec 13))",file=f)   # L1
		print(f"(declare-fun yT_{i} () (_ BitVec 19))",file=f)   # L2

	for i in range(nE0+1,rds+1):
		print(f"(declare-fun xB_{i} () (_ BitVec 13))",file=f)   # L1
		print(f"(declare-fun yB_{i} () (_ BitVec 19))",file=f)   # L2

	for i in range(nE0,fwd_rds):
		print(f"(declare-fun uxT_{i} () (_ BitVec 13))",file=f)   # L1
		print(f"(declare-fun uyT_{i} () (_ BitVec 19))",file=f)   # L2

	for i in range(nE0+1,fwd_rds+1):
		print(f"(declare-fun uxB_{i} () (_ BitVec 13))",file=f)   # L1
		print(f"(declare-fun uyB_{i} () (_ BitVec 19))",file=f)   # L2


	# creating variables : AL1, AL2
	for i in range(fwd_rds-1):
		print(f"(declare-fun AL1T_{i} () (_ BitVec 1)) ",file=f)   # L1
		print(f"(declare-fun AL2T_{i} () (_ BitVec 1)) ",file=f)   # L2
		print(f"(declare-fun nx0T_{i} () (_ BitVec 1)) ",file=f)   # L1
		print(f"(declare-fun ny0T_{i} () (_ BitVec 1)) ",file=f)   # L2

	for i in range(nE0+1,rds):
		print(f"(declare-fun AL1B_{i} () (_ BitVec 1)) ",file=f)   # L1
		print(f"(declare-fun AL2B_{i} () (_ BitVec 1)) ",file=f)   # L2
		print(f"(declare-fun nx0B_{i} () (_ BitVec 1)) ",file=f)   # L1
		print(f"(declare-fun ny0B_{i} () (_ BitVec 1)) ",file=f)   # L2

	print(f"(declare-fun kT () (_ BitVec {2*rds}))",file=f)
	print(f"(declare-fun kB () (_ BitVec {2*rds}))",file=f)


	for i in range(nE0,fwd_rds-1):
		print(f"(declare-fun PAY1T_{i} () (_ BitVec 1)) ",file=f)
		print(f"(declare-fun PAY2T_{i} () (_ BitVec 1)) ",file=f)


	for i in range(nE0+1,fwd_rds):
		print(f"(declare-fun PAY1B_{i} () (_ BitVec 1)) ",file=f)
		print(f"(declare-fun PAY2B_{i} () (_ BitVec 1)) ",file=f)


	print(f"(declare-fun summary_pay () (_ BitVec {4*(nE0+nEm+nE1-1)}))",file=f)


	#Associate all payments in one vector
	for i in range(nE0):
		print(f"(assert (= {bit('summary_pay',4*i)} AL1T_{i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*i+1)} AL1T_{i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*i+2)} AL2T_{i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*i+3)} AL2T_{i}) ) ",file=f)

	for i in range(nEm-1):
		print(f"(assert (= {bit('summary_pay',4*(i+nE0))} PAY1T_{nE0+i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0)+1)} PAY2T_{nE0+i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0)+2)} PAY1B_{nE0+i+1}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0)+3)} PAY2B_{nE0+i+1}) ) ",file=f)

	for i in range(nE1):
		print(f"(assert (= {bit('summary_pay',4*(i+nE0+nEm-1))} AL1B_{nE0+nEm+i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0+nEm-1)+1)} AL1B_{nE0+nEm+i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0+nEm-1)+2)} AL2B_{nE0+nEm+i}) ) ",file=f)
		print(f"(assert (= {bit('summary_pay',4*(i+nE0+nEm-1)+3)} AL2B_{nE0+nEm+i}) ) ",file=f)


	#key schedule
	print(f"(assert (= ((_ extract  {2*rds-1} 80) kT)  (bvxor (bvxor ((_ extract {2*rds-81} 0) kT) ((_ extract  {2*rds-62} 19) kT))  (bvxor ((_ extract  {2*rds-51} 30) kT) ((_ extract  {2*rds-14} 67) kT))))) ",file=f)
	print(f"(assert (= ((_ extract  {2*rds-1} 80) kB)  (bvxor (bvxor ((_ extract  {2*rds-81} 0) kB) ((_ extract  {2*rds-62} 19) kB))  (bvxor ((_ extract  {2*rds-51} 30) kB) ((_ extract  {2*rds-14} 67) kB)))))",file=f)
	if sk:
		print(f"(assert (= kT {i2v(0,2*rds)}))",file=f)
		print(f"(assert (= kB {i2v(0,2*rds)}))",file=f)

	#Force activity
	print(f"(assert( or (or (not (= xT_0 {i2v(0,13)})) (not (= yT_0 {i2v(0,19)}))) (not (= kT {i2v(0,2*rds)}))))",file=f)
	print(f"(assert( or (or (not (= xB_{rds} {i2v(0,13)})) (not (= yB_{rds} {i2v(0,19)}))) (not (= kB {i2v(0,2*rds)}))))",file=f)


	# equality of the shifted bits
	for i in range(fwd_rds-1):
		print(f"(assert (= (bvlshr xT_{i} {i2v(1,13)}) (bvand xT_{i+1} {i2v(2**12-1,13)}) ) ) ",file=f)
		print(f"(assert (= (bvlshr yT_{i} {i2v(1,19)}) (bvand yT_{i+1} {i2v(2**18-1,19)}) ) ) ",file=f)
	for i in range(nE0+1,rds):
		print(f"(assert (= (bvlshr xB_{i} {i2v(1,13)}) (bvand xB_{i+1} {i2v(2**12-1,13)}) ) ) ",file=f)
		print(f"(assert (= (bvlshr yB_{i} {i2v(1,19)}) (bvand yB_{i+1} {i2v(2**18-1,19)}) ) ) ",file=f)



	# Forward differential
	for i in range(nE0):
		# compute AL1 ie, activity of the AND in register L2
		print(f"(assert (=  AL1T_{i} (bvor (bvor ((_ extract 6 6) yT_{i}) ((_ extract 8 8) yT_{i}) ) (bvor ((_ extract 10 10) yT_{i})  ((_ extract 15 15) yT_{i}) ) )  ))",file=f)
		# compute AL2 ie, activity of the AND in register L1
		print(f"(assert (=   AL2T_{i} (bvor ((_ extract 7 7) xT_{i})  ((_ extract 4 4) xT_{i}) ) ) )",file=f)
		# compute nx0
		print(f"(assert (=  nx0T_{i}  (bvxor ((_ extract {2*i+1} {2*i+1}) kT)  (bvxor  ((_ extract 0 0) yT_{i})   ((_ extract 11 11) yT_{i})))))",file=f) # nx0 = y_18 + y_7
		# compute ny0
		if(IR[i]==0):
			print(f"(assert (= ny0T_{i}  (bvxor ((_ extract {2*i} {2*i}) kT) (bvxor  ((_ extract 0 0) xT_{i})   ((_ extract 5 5) xT_{i})))))",file=f) # ny0 = x_12 + x_7
		else :
			print(f"(assert (=  ny0T_{i}  (bvxor (bvxor  ((_ extract 0 0) xT_{i})   ((_ extract 5 5) xT_{i}))  (bvxor ((_ extract {2*i} {2*i}) kT) ((_ extract 9 9) xT_{i})))   ))",file=f) # ny0 = x_12 + x_7 + x_3
		# assign nx0 to the msb of x if AL = 0
		print(f"(assert (= #b0  (bvand (bvxor ((_ extract 12 12) xT_{i+1}) nx0T_{i} ) (bvxor AL1T_{i} #b1  ) )  ) )",file=f)
		# assign ny0 to the msb of y if AL = 0
		print(f"(assert (= #b0  (bvand (bvxor ((_ extract 18 18) yT_{i+1}) ny0T_{i} ) (bvxor AL2T_{i} #b1  ) )  ) )",file=f)


	# Backward differential
	for i in range(fwd_rds,rds):
		# compute AL1 ie, activity of the AND in register L2
		print(f"(assert (=  AL1B_{i} (bvor (bvor ((_ extract 6 6) yB_{i}) ((_ extract 8 8) yB_{i}) ) (bvor ((_ extract 10 10) yB_{i})  ((_ extract 15 15) yB_{i}) ) )  ))",file=f)
		# compute AL2 ie, activity of the AND in register L1
		print(f"(assert (=   AL2B_{i} (bvor ((_ extract 7 7) xB_{i})  ((_ extract 4 4) xB_{i}) ) ) )",file=f)
		# compute nx0
		print(f"(assert (=  nx0B_{i}  (bvxor ((_ extract {2*i+1} {2*i+1}) kB) (bvxor  ((_ extract 0 0) yB_{i})   ((_ extract 11 11) yB_{i})))))",file=f) # nx0 = y_18 + y_7
		# compute ny0
		if(IR[i]==0):
			print(f"(assert (= ny0B_{i}  (bvxor ((_ extract {2*i} {2*i}) kB) (bvxor  ((_ extract 0 0) xB_{i})   ((_ extract 5 5) xB_{i})))))",file=f) # ny0 = x_12 + x_7
		else :
			print(f"(assert (=  ny0B_{i}  (bvxor (bvxor  ((_ extract 0 0) xB_{i})   ((_ extract 5 5) xB_{i}))  (bvxor ((_ extract {2*i} {2*i}) kB) ((_ extract 9 9) xB_{i})))   ))",file=f) # ny0 = x_12 + x_7 + x_3
		# assign ny0 to the msb of y if AL = 0
		print(f"(assert (= #b0  (bvand (bvxor ((_ extract 12 12) xB_{i+1}) nx0B_{i} ) (bvxor AL1B_{i} #b1  ) )  ) )",file=f)
		# assign nx0 to the msb of x if AL = 0
		print(f"(assert (= #b0  (bvand (bvxor ((_ extract 18 18) yB_{i+1}) ny0B_{i} ) (bvxor AL2B_{i} #b1  ) )  ) )",file=f)

	# Middle part
	print(f"(assert (=  uxT_{nE0} {i2v(0,13)} ))",file=f)
	print(f"(assert (=  uyT_{nE0} {i2v(0,19)} ))",file=f)
	print(f"(assert (=  uxB_{fwd_rds} {i2v(0,13)} ))",file=f)
	print(f"(assert (=  uyB_{fwd_rds} {i2v(0,19)} ))",file=f)

	# Normalization (ux = 1 => x = 0)
	for i in range(nE0,fwd_rds):
		print(f"(assert (=  (bvand uxT_{i}  xT_{i}) {i2v(0,13)} ))",file=f)
		print(f"(assert (=  (bvand uyT_{i}  yT_{i}) {i2v(0,19)} ))",file=f)
	for i in range(nE0+1,fwd_rds+1):
		print(f"(assert (=  (bvand uxB_{i}  xB_{i}) {i2v(0,13)} ))",file=f)
		print(f"(assert (=  (bvand uyB_{i}  yB_{i}) {i2v(0,19)} ))",file=f)


	#shifting
	for i in range(nE0,fwd_rds-1):
		print(f"(assert (= (bvlshr uxT_{i} {i2v(1,13)}) (bvand uxT_{i+1} {i2v(2**12-1,13)}) ) ) ",file=f)
		print(f"(assert (= (bvlshr uyT_{i} {i2v(1,19)}) (bvand uyT_{i+1} {i2v(2**18-1,19)}) ) ) ",file=f)
	for i in range(nE0+1,fwd_rds):
		print(f"(assert (= (bvlshr uxB_{i} {i2v(1,13)}) (bvand uxB_{i+1} {i2v(2**12-1,13)}) ) ) ",file=f)
		print(f"(assert (= (bvlshr uyB_{i} {i2v(1,19)}) (bvand uyB_{i+1} {i2v(2**18-1,19)}) ) ) ",file=f)


	# forward AND
	for i in range(nE0,fwd_rds-1):
		# compute AL1 ie, whether there's a known active AND bit in register L2
		print(f"(assert (=  AL1T_{i} (bvor (bvor ((_ extract 6 6) yT_{i}) ((_ extract 8 8) yT_{i}) ) (bvor ((_ extract 10 10) yT_{i})  ((_ extract 15 15) yT_{i}) ) )  ))",file=f)
		# compute whether operation is unworkable (ie, inactive + unknown)
		print(f"(assert (= (bvand (bvnot AL1T_{i}) ((_ extract 12 12 ) uxT_{i+1}) ) (bvand (bvnot AL1T_{i}) (bvor (bvor ((_ extract 11 11) uyT_{i}) ((_ extract 0 0) uyT_{i})) (bvor (bvor ((_ extract 6 6) uyT_{i}) ((_ extract 8 8) uyT_{i}) ) (bvor ((_ extract 10 10) uyT_{i})  ((_ extract 15 15) uyT_{i}) )))))) ",file=f)
		# AND not active + known bit => fixed value
		print(f"(assert (= (bvand (bvand (bvnot AL1T_{i}) (bvnot ((_ extract 12 12 ) uxT_{i+1}))) ((_ extract 12 12 ) xT_{i+1}) ) (bvand (bvand (bvnot AL1T_{i}) (bvnot ((_ extract 12 12 ) uxT_{i+1}))) (bvxor ((_ extract {2*i+1} {2*i+1}) kT)  (bvxor  ((_ extract 0 0) yT_{i})   ((_ extract 11 11) yT_{i})))))) ",file=f)


		# compute AL2 ie, whether there's a known active AND bit in register L1
		print(f"(assert (= AL2T_{i} (bvor ((_ extract 7 7) xT_{i})  ((_ extract 4 4) xT_{i}) ) ) )",file=f)
		if(IR[i] == 0):
			# compute whether operation is unworkable (ie, inactive + unknown)
			print(f"(assert (= (bvand (bvnot AL2T_{i}) {bit(f'uyT_{i+1}',18)} ) (bvand (bvnot AL2T_{i}) (bvor (bvor {bit(f'uxT_{i}',7)}  {bit(f'uxT_{i}',4)} ) (bvor {bit(f'uxT_{i}',0)} {bit(f'uxT_{i}',5)})  )) ))",file=f)
			print(f"(assert (= (bvand (bvand (bvnot AL2T_{i}) (bvnot {bit(f'uyT_{i+1}',18)})) {bit(f'yT_{i+1}',18)} ) (bvand (bvand (bvnot AL2T_{i}) (bvnot {bit(f'uyT_{i+1}',18)}) ) (bvxor {bit('kT',2*i)}  (bvxor  {bit(f'xT_{i}',0)}   {bit(f'xT_{i}',5)}))))) ",file=f)
		else:
			print(f"(assert (= (bvand (bvnot AL2T_{i}) {bit(f'uyT_{i+1}',18)} ) (bvand (bvnot AL2T_{i}) (bvor (bvor {bit(f'uxT_{i}',7)}  {bit(f'uxT_{i}',4)} ) (bvor {bit(f'uxT_{i}',0)} (bvor {bit(f'uxT_{i}',5)} {bit(f'uxT_{i}',9)}))  )) ))",file=f)
			print(f"(assert (= (bvand (bvand (bvnot AL2T_{i}) (bvnot {bit(f'uyT_{i+1}',18)})) {bit(f'yT_{i+1}',18)} ) (bvand (bvand (bvnot AL2T_{i}) (bvnot {bit(f'uyT_{i+1}',18)}) ) (bvxor (bvxor {bit('kT',2*i)}  {bit(f'xT_{i}',9)}) (bvxor  {bit(f'xT_{i}',0)}   {bit(f'xT_{i}',5)}))))) ",file=f)


		# If active, PAY <=> known
		print(f"(assert (= PAY1T_{i} (bvand AL1T_{i} (bvnot ((_ extract 12 12 ) uxT_{i+1})))))",file=f)
		print(f"(assert (= PAY2T_{i} (bvand AL2T_{i} (bvnot ((_ extract 18 18 ) uyT_{i+1})))))",file=f)

	# backward AND
	for i in range(nE0+1,fwd_rds):
		# compute AL1 ie, whether there's a known active AND bit in register L2
		print(f"(assert (=  AL1B_{i} (bvor (bvor ((_ extract 6 6) yB_{i}) ((_ extract 8 8) yB_{i}) ) (bvor ((_ extract 10 10) yB_{i})  ((_ extract 15 15) yB_{i}) ) )  ))",file=f)
		# compute whether operation is unworkable (ie, inactive + unknown)
		print(f"(assert (= (bvand (bvnot AL1B_{i}) {bit(f'uyB_{i}',0)} ) (bvand (bvnot AL1B_{i}) (bvor (bvor ((_ extract 11 11) uyB_{i}) {bit(f'uxB_{i+1}',12)}) (bvor (bvor ((_ extract 6 6) uyB_{i}) ((_ extract 8 8) uyB_{i}) ) (bvor ((_ extract 10 10) uyB_{i})  ((_ extract 15 15) uyB_{i}) )))))) ",file=f)
		# AND not active + known bit => fixed value
		print(f"(assert (= (bvand (bvand (bvnot AL1B_{i}) (bvnot {bit(f'uyB_{i}',0)})) {bit(f'yB_{i}',0)} ) (bvand (bvand (bvnot AL1B_{i}) (bvnot {bit(f'uyB_{i}',0)})) (bvxor ((_ extract {2*i+1} {2*i+1}) kB)  (bvxor  {bit(f'xB_{i+1}',12)}   ((_ extract 11 11) yB_{i})))))) ",file=f)


		# compute AL2 ie, whether there's a known active AND bit in register L1
		print(f"(assert (= AL2B_{i} (bvor ((_ extract 7 7) xB_{i})  ((_ extract 4 4) xB_{i}) ) ) )",file=f)
		if(IR[i] == 0):
			# compute whether operation is unworkable (ie, inactive + unknown)
			print(f"(assert (= (bvand (bvnot AL2B_{i}) {bit(f'uxB_{i}',0)} ) (bvand (bvnot AL2B_{i}) (bvor (bvor {bit(f'uxB_{i}',7)}  {bit(f'uxB_{i}',4)} ) (bvor {bit(f'uyB_{i+1}',18)} {bit(f'uxB_{i}',5)})  )) ))",file=f)
			print(f"(assert (= (bvand (bvand (bvnot AL2B_{i}) (bvnot {bit(f'uxB_{i}',0)})) {bit(f'xB_{i}',0)} ) (bvand (bvand (bvnot AL2B_{i}) (bvnot {bit(f'uxB_{i}',0)}) ) (bvxor {bit('kB',2*i)}  (bvxor  {bit(f'yB_{i+1}',18)}   {bit(f'xB_{i}',5)}))))) ",file=f)
		else:
			print(f"(assert (= (bvand (bvnot AL2B_{i}) {bit(f'uxB_{i}',0)} ) (bvand (bvnot AL2B_{i}) (bvor (bvor {bit(f'uxB_{i}',7)}  {bit(f'uxB_{i}',4)} ) (bvor {bit(f'uyB_{i+1}',18)} (bvor {bit(f'uxB_{i}',5)} {bit(f'uxB_{i}',9)}))  )) ))",file=f)
			print(f"(assert (= (bvand (bvand (bvnot AL2B_{i}) (bvnot {bit(f'uxB_{i}',0)})) {bit(f'xB_{i}',0)} ) (bvand (bvand (bvnot AL2B_{i}) (bvnot {bit(f'uxB_{i}',0)}) ) (bvxor (bvxor {bit('kB',2*i)}  {bit(f'xB_{i}',9)}) (bvxor  {bit(f'yB_{i+1}',18)}   {bit(f'xB_{i}',5)}))))) ",file=f)


		# If active, PAY <=> known
		print(f"(assert (= PAY1B_{i} (bvand AL1B_{i} (bvnot {bit(f'uyB_{i}',0)}))))",file=f)
		print(f"(assert (= PAY2B_{i} (bvand AL2B_{i} (bvnot {bit(f'uxB_{i}',0)}))))",file=f)

	#BCT constraints
	for i in range(nE0,fwd_rds):
		# force known value of all BCT and
		print(f"(assert (= #b0 (bvand {bit(f'uyT_{i}',6)} (bvor {bit(f'yB_{i+1}',7)} {bit(f'uyB_{i+1}',7)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyB_{i+1}',7)} (bvor {bit(f'yT_{i}',6)} {bit(f'uyT_{i}',6)}) )))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyT_{i}',8)} (bvor {bit(f'yB_{i+1}',5)} {bit(f'uyB_{i+1}',5)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyB_{i+1}',5)} (bvor {bit(f'yT_{i}',8)} {bit(f'uyT_{i}',8)}) )))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyT_{i}',10)} (bvor {bit(f'yB_{i+1}',14)} {bit(f'uyB_{i+1}',14)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyB_{i+1}',14)} (bvor {bit(f'yT_{i}',10)} {bit(f'uyT_{i}',10)}) )))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyT_{i}',15)} (bvor {bit(f'yB_{i+1}',9)} {bit(f'uyB_{i+1}',9)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uyB_{i+1}',9)} (bvor {bit(f'yT_{i}',15)} {bit(f'uyT_{i}',15)}) )))",file=f)

		print(f"(assert (= #b0 (bvand {bit(f'uxT_{i}',7)} (bvor {bit(f'xB_{i+1}',3)} {bit(f'uxB_{i+1}',3)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uxB_{i+1}',3)} (bvor {bit(f'xT_{i}',7)} {bit(f'uxT_{i}',7)}) )))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uxT_{i}',4)} (bvor {bit(f'xB_{i+1}',6)} {bit(f'uxB_{i+1}',6)}))))",file=f)
		print(f"(assert (= #b0 (bvand {bit(f'uxB_{i+1}',6)} (bvor {bit(f'xT_{i}',4)} {bit(f'uxT_{i}',4)}) )))",file=f)

		# Constraint = 0 for AL1
		print(f"(assert (= #b0 (bvxor (bvxor (bvand {bit(f'yT_{i}',6)}   {bit(f'yB_{i+1}',7)}) (bvand {bit(f'yT_{i}',8)}   {bit(f'yB_{i+1}',5)})  ) (bvxor (bvand {bit(f'yT_{i}',10)}   {bit(f'yB_{i+1}',14)}) (bvand {bit(f'yT_{i}',15)}   {bit(f'yB_{i+1}',9)})  ))))",file=f)
		# Constraint = 0 for AL2
		print(f"(assert (= #b0 (bvxor (bvand {bit(f'xT_{i}',7)}   {bit(f'xB_{i+1}',3)}) (bvand {bit(f'xT_{i}',4)}   {bit(f'xB_{i+1}',6)})  )))",file=f)





def hamming_weight(nbr,f, fun_name="w_H"):
	i= 0
	call = "x"
	nb = nbr
	while(nb > 0):
		mask = "#b"+((("0"*(2**i)+"1"*(2**i))*nbr)[-nbr:])
		print(f" (define-fun {fun_name}{i} ((x (_ BitVec {nbr}))) (_ BitVec {nbr}) (bvadd (bvand x {mask} ) (bvand (bvlshr x {i2v(2**i,nbr)}) {mask} )))",file=f)
		call = f"({fun_name}{i} {call})"
		i=i+1
		nb = int(nb/2)
	print(f" (define-fun {fun_name} ((x (_ BitVec {nbr}))) (_ BitVec {nbr}) {call})",file=f)



def objective(obj,nbr,f):
	print(f"(assert (=  {i2v(obj,nbr)} (w_H summary_pay) ))",file=f)

def footer(nE0,nEm,nE1,f):

	print("(check-sat)",file=f)

	for i in range(nE0+nEm):
		print(f"(get-value ( xT_{i}))",file=f)
		print(f"(get-value ( yT_{i}))",file=f)

	for i in range(nE0,nE0+nEm):
		print(f"(get-value ( uxT_{i}))",file=f)
		print(f"(get-value ( uyT_{i}))",file=f)


	for i in range(nE0+1,nE0+nEm+nE1+1):
		print(f"(get-value ( xB_{i}))",file=f)
		print(f"(get-value ( yB_{i}))",file=f)

	for i in range(nE0+1,nE0+nEm+1):
		print(f"(get-value ( uxB_{i}))",file=f)
		print(f"(get-value ( uyB_{i}))",file=f)


	print(f"(get-value ( xT_0))",file=f)
	print(f"(get-value ( yT_0))",file=f)

	print(f"(get-value ( xB_{nE0+nEm+nE1}))",file=f)
	print(f"(get-value ( yB_{nE0+nEm+nE1}))",file=f)

	print(f"(get-value ( kT))",file=f)
	print(f"(get-value ( kB))",file=f)

	for i in range(nE0+nEm-1):
		print(f"(get-value ( AL1T_{i}))",file=f)
		print(f"(get-value ( AL2T_{i}))",file=f)

	for i in range(nE0,nE0+nEm-1):
			print(f"(get-value ( PAY1T_{i}))",file=f)
			print(f"(get-value ( PAY2T_{i}))",file=f)
			print(f"(get-value ( PAY1B_{i+1}))",file=f)
			print(f"(get-value ( PAY2B_{i+1}))",file=f)



	for i in range(nE0+nEm,nE0+nEm+nE1):
		print(f"(get-value ( AL1B_{i}))",file=f)
		print(f"(get-value ( AL2B_{i}))",file=f)


	print("(exit)",file=f)

	
	

def main():
	nE0 = int(sys.argv[1])
	nEm = int(sys.argv[2])
	nE1 = int(sys.argv[3])
	obj = int(sys.argv[4])
	f = sys.stdout
	if len(sys.argv) > 5:
		f = open(sys.argv[5],'w')
	header(f)
	hamming_weight(4*(nE0+nEm+nE1-1),f)
	core(nE0,nEm,nE1,f)
	objective(obj,4*(nE0+nEm+nE1-1),f)
	footer(nE0,nEm,nE1,f)
	f.close()


if __name__ == '__main__':
	main()
