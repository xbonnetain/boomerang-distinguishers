%
% Authors: Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
%
% Impossible boomerang code built upon the impossible differential code from https://eprint.iacr.org/2022/1147
%
%


% number of parallel tweak lines in the tweak schedule
int: NPT = 4;
% the length of upper trail throughout the distinguisher part
int: RU = 10;
% the length of lower trail throughout the distinguisher part
int: RL = 11;
% the length of distinguisher
int: RT;
RT = RU + RL;
                                                           
int: block_size;
int: cell_size = 4;
block_size = 16*cell_size;



constraint assert(RU >= 1, "Invalid value for RU: " ++
                  "RU must be greater than or equal to 1");

constraint assert(RL >= 1, "Invalid value for RL: " ++
                  "RL must be greater than or equal to 1");

constraint assert(NPT == 4, "Invalid value for NPT: " ++
                  "NPT must be 4 for SKINNYee");

constraint assert(cell_size == 4, "cell_size must be 4 for SKINNYee");

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%  ____          __  _                _                   _                    _____       _      _            
% |  _ \   ___  / _|(_) _ __    ___  | |     ___    ___  | | __ _   _  _ __   |_   _|__ _ | |__  | |  ___  ___ 
% | | | | / _ \| |_ | || '_ \  / _ \ | |    / _ \  / _ \ | |/ /| | | || '_ \    | | / _` || '_ \ | | / _ \/ __|
% | |_| ||  __/|  _|| || | | ||  __/ | |___| (_) || (_) ||   < | |_| || |_) |   | || (_| || |_) || ||  __/\__ \
% |____/  \___||_|  |_||_| |_| \___| |_____|\___/  \___/ |_|\_\ \__,_|| .__/    |_| \__,_||_.__/ |_| \___||___/
%                                                                     |_|                 
% define lookup tables

% skinny round permutation (shiftrows)
array[0..15] of int: round_permutation = array1d(0..15, [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12]);
% skinny tweak permutation
array[0..15] of int: inv_tweak_permutation = array1d(0..15, [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1]);

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%   ____                    _                _         _           __                _____                        _      ____         _                _         _       
%  / ___| ___   _ __   ___ | |_  _ __  __ _ (_) _ __  | |_  ___   / _|  ___   _ __  |_   _|__      __ ___   __ _ | | __ / ___|   ___ | |__    ___   __| | _   _ | |  ___ 
% | |    / _ \ | '_ \ / __|| __|| '__|/ _` || || '_ \ | __|/ __| | |_  / _ \ | '__|   | |  \ \ /\ / // _ \ / _` || |/ / \___ \  / __|| '_ \  / _ \ / _` || | | || | / _ \
% | |___| (_) || | | |\__ \| |_ | |  | (_| || || | | || |_ \__ \ |  _|| (_) || |      | |   \ V  V /|  __/| (_| ||   <   ___) || (__ | | | ||  __/| (_| || |_| || ||  __/
%  \____|\___/ |_| |_||___/ \__||_|   \__,_||_||_| |_| \__||___/ |_|   \___/ |_|      |_|    \_/\_/  \___| \__,_||_|\_\ |____/  \___||_| |_| \___| \__,_| \__,_||_| \___|
%                                                                                                                                                                               

array[0..(RT - 1), 0..15] of var int: inv_tkp;
constraint forall(i in 0..15) (inv_tkp[0, i] = i);
constraint forall(r in 1..(RT - 1), i in 0..15)
(
    inv_tkp[r, i] = inv_tweak_permutation[inv_tkp[r - 1, i]]
);

%%% UPPER TWEAK MANAGEMENT (Over the RT rounds (ie, all))

array[0..15] of var 0..1: LANEU; % activeness pattern in each lane through EB + EU + EL + EF
array[0..(RT - 1), 0..15] of var 0..1: ASTKU; % activeness pattern in each round tweak through EB + EU + EL + EF
array[0..(RT - 1), 0..15] of var -2..15: DSTKU; % difference value in each round tweak through EB + EU + EL + EF

constraint forall(r in 0..(RT - 1), i in 0..15)
(
    link_difference(ASTKU[r, i], DSTKU[r, i])
);

constraint forall(i in 0..15)
(
    forall(r in 0..(RT - 1)) (ASTKU[r, inv_tkp[r, i]] - LANEU[i] <= 0)
    /\
    sum(r in 0..(RT - 1))(ASTKU[r, inv_tkp[r, i]]) - RT*LANEU[i] >= (1 - NPT)  % maximum of 3 cancellations
);

%%% LOWER TWEAK MANAGEMENT

array[0..15] of var 0..1: LANEL; % activeness pattern in each lane through EB + EU + EL + EF
array[0..(RT - 1), 0..15] of var 0..1: ASTKL; % activeness pattern in each round tweak through EB + EU + EL + EF
array[0..(RT - 1), 0..15] of var -2..15: DSTKL; % difference value in each round tweak through EB + EU + EL + EF

constraint forall(r in 0..(RT - 1), i in 0..15)
(
    link_difference(ASTKL[r, i], DSTKL[r, i])
);

constraint forall(i in 0..15)
(
    forall(r in 0..(RT - 1)) (ASTKL[r, inv_tkp[r, i]] - LANEL[i] <= 0)
    /\
    sum(r in 0..(RT - 1))(ASTKL[r, inv_tkp[r, i]]) - RT*LANEL[i] >= (1 - NPT) % maximum of 3 cancellations
);

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%   ____                    _                _         _           __                _____  _   _ 
%  / ___| ___   _ __   ___ | |_  _ __  __ _ (_) _ __  | |_  ___   / _|  ___   _ __  | ____|| | | |
% | |    / _ \ | '_ \ / __|| __|| '__|/ _` || || '_ \ | __|/ __| | |_  / _ \ | '__| |  _|  | | | |
% | |___| (_) || | | |\__ \| |_ | |  | (_| || || | | || |_ \__ \ |  _|| (_) || |    | |___ | |_| |
%  \____|\___/ |_| |_||___/ \__||_|   \__,_||_||_| |_| \__||___/ |_|   \___/ |_|    |_____| \___/ 
%



array[0..RU, 0..15] of var 0..3: AXU;
array[0..RU, 0..15] of var -2..15: DXU;
constraint forall(i in 0..RU, j in 0..15) (
    link_difference(AXU[i,j], DXU[i,j])
);

array[0..(RU - 1), 0..15] of var 0..3: AYU;
array[0..(RU - 1), 0..15] of var -2..15: DYU;
constraint forall(i in 0..(RU - 1), j in 0..15) (
    link_difference(AYU[i,j], DYU[i,j])
);

array[0..(RU - 1), 0..15] of var 0..3: AZU;
array[0..(RU - 1), 0..15] of var -2..15: DZU;
constraint forall(i in 0..(RU - 1), j in 0..15) (
    link_difference(AZU[i,j], DZU[i,j])
);

% exclude all-zero input difference
constraint sum(i in 0..15)(AXU[0, i]) + sum(i in 0..15)(LANEU[i]) != 0;

% S-box
constraint forall(r in 0..(RU - 1), i in 0..15)
(
    sbox(AXU[r, i], AYU[r, i])
);

% xor with round tweak
constraint forall(r in 0..(RU - 1), i in 0..7)
(
    xor_operation(AYU[r, i], DYU[r, i], ASTKU[r, i], DSTKU[r, i], AZU[r, i], DZU[r, i])
    /\
    AZU[r, i + 8] = AYU[r, i + 8]
    /\
    DZU[r, i + 8] = DYU[r, i + 8]
);

% mix-column and shift-rows
constraint forall(r in 0..(RU - 1), i in 0..3)
(
    mix_column_forward(AZU[r, round_permutation[i]], DZU[r, round_permutation[i]],
                       AZU[r, round_permutation[i + 4]], DZU[r, round_permutation[i + 4]],
                       AZU[r, round_permutation[i + 8]], DZU[r, round_permutation[i + 8]],
                       AZU[r, round_permutation[i + 12]], DZU[r, round_permutation[i + 12]],
                       AXU[r + 1, i], DXU[r + 1, i],
                       AXU[r + 1, i + 4], DXU[r + 1, i + 4],
                       AXU[r + 1, i + 8], DXU[r + 1, i + 8],
                       AXU[r + 1, i + 12], DXU[r + 1, i + 12])
);

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%   ____                    _                _         _           __                _____  _     
%  / ___| ___   _ __   ___ | |_  _ __  __ _ (_) _ __  | |_  ___   / _|  ___   _ __  | ____|| |    
% | |    / _ \ | '_ \ / __|| __|| '__|/ _` || || '_ \ | __|/ __| | |_  / _ \ | '__| |  _|  | |    
% | |___| (_) || | | |\__ \| |_ | |  | (_| || || | | || |_ \__ \ |  _|| (_) || |    | |___ | |___ 
%  \____|\___/ |_| |_||___/ \__||_|   \__,_||_||_| |_| \__||___/ |_|   \___/ |_|    |_____||_____|
% constraints for EL

array[0..RL, 0..15] of var 0..3: AXL;
array[0..RL, 0..15] of var -2..15: DXL;
constraint forall(i in 0..RL, j in 0..15) (
    link_difference(AXL[i,j], DXL[i,j])
);

array[0..(RL - 1), 0..15] of var 0..3: AYL;
array[0..(RL - 1), 0..15] of var -2..15: DYL;
constraint forall(i in 0..(RL - 1), j in 0..15) (
    link_difference(AYL[i,j], DYL[i,j])
);

array[0..(RL - 1), 0..15] of var 0..3: AZL;
array[0..(RL - 1), 0..15] of var -2..15: DZL;
constraint forall(i in 0..(RL - 1), j in 0..15) (
    link_difference(AZL[i,j], DZL[i,j])
);

% exclude all-zero output difference
constraint sum(i in 0..15)(AXL[RL, i]) + sum(i in 0..15)(LANEL[i]) != 0;

% mix-column and shift-rows
constraint forall(r in 0..(RL - 1), i in 0..3)
(
    mix_column_backward(AXL[r + 1, i], DXL[r + 1, i],
                        AXL[r + 1, i + 4], DXL[r + 1, i + 4],
                        AXL[r + 1, i + 8], DXL[r + 1, i + 8],
                        AXL[r + 1, i + 12], DXL[r + 1, i + 12],
                        AZL[r, round_permutation[i]], DZL[r, round_permutation[i]],
                        AZL[r, round_permutation[i + 4]], DZL[r, round_permutation[i + 4]],
                        AZL[r, round_permutation[i + 8]], DZL[r, round_permutation[i + 8]],
                        AZL[r, round_permutation[i + 12]], DZL[r, round_permutation[i + 12]])
);

% xor with round tweak
constraint forall(r in 0..(RL - 1), i in 0..7)
(
    xor_operation(AZL[r, i], DZL[r, i], ASTKL[ RU + r, i], DSTKL[ RU + r, i], AYL[r, i], DYL[r, i])
    /\
    AYL[r, i + 8] = AZL[r, i + 8]
    /\
    DYL[r, i + 8] = DZL[r, i + 8]
);

% S-box
constraint forall(r in 0..(RL - 1), i in 0..15)
(
    sbox(AYL[r, i], AXL[r, i])
);

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%   ____                    _                _         _           __                _    _             __  __              _    _                 ____         _         _   
%  / ___| ___   _ __   ___ | |_  _ __  __ _ (_) _ __  | |_  ___   / _|  ___   _ __  | |_ | |__    ___  |  \/  |  ___   ___ | |_ (_) _ __    __ _  |  _ \  ___  (_) _ __  | |_ 
% | |    / _ \ | '_ \ / __|| __|| '__|/ _` || || '_ \ | __|/ __| | |_  / _ \ | '__| | __|| '_ \  / _ \ | |\/| | / _ \ / _ \| __|| || '_ \  / _` | | |_) |/ _ \ | || '_ \ | __|
% | |___| (_) || | | |\__ \| |_ | |  | (_| || || | | || |_ \__ \ |  _|| (_) || |    | |_ | | | ||  __/ | |  | ||  __/|  __/| |_ | || | | || (_| | |  __/| (_) || || | | || |_ 
%  \____|\___/ |_| |_||___/ \__||_|   \__,_||_||_| |_| \__||___/ |_|   \___/ |_|     \__||_| |_| \___| |_|  |_| \___| \___| \__||_||_| |_| \__, | |_|    \___/ |_||_| |_| \__|
%                                                                                                                                          |___/                              
% 


constraint ( 
              ((AXU[RU,  0] == 1) /\ (AYL[0,  0] == 1)) \/  
              ((AXU[RU,  1] == 1) /\ (AYL[0,  1] == 1)) \/ 
              ((AXU[RU,  2] == 1) /\ (AYL[0,  2] == 1)) \/ 
              ((AXU[RU,  3] == 1) /\ (AYL[0,  3] == 1)) \/ 
%              
              ((AXU[RU,  4] == 1) /\ (AYL[0,  4] == 1)) \/ 
              ((AXU[RU,  5] == 1) /\ (AYL[0,  5] == 1)) \/ 
              ((AXU[RU,  6] == 1) /\ (AYL[0,  6] == 1)) \/ 
              ((AXU[RU,  7] == 1) /\ (AYL[0,  7] == 1)) \/ 
%
              ((AXU[RU,  8] == 1) /\ (AYL[0,  8] == 1))   \/  
              ((AXU[RU,  9] == 1) /\ (AYL[0,  9] == 1))   \/ 
              ((AXU[RU,  10] == 1) /\ (AYL[0,  10] == 1)) \/ 
              ((AXU[RU,  11] == 1) /\ (AYL[0,  11] == 1)) \/ 
%              
              ((AXU[RU,  12] == 1) /\ (AYL[0,  12] == 1)) \/ 
              ((AXU[RU,  13] == 1) /\ (AYL[0,  13] == 1)) \/ 
              ((AXU[RU,  14] == 1) /\ (AYL[0,  14] == 1)) \/ 
              ((AXU[RU,  15] == 1) /\ (AYL[0,  15] == 1)) 
);



% #############################################################################################################################################

solve satisfy;

% #############################################################################################################################################
% #############################################################################################################################################
% #############################################################################################################################################
%     _                 _  _  _                       _____                     _    _                    
%    / \   _   _ __  __(_)| |(_)  __ _  _ __  _   _  |  ___|_   _  _ __    ___ | |_ (_)  ___   _ __   ___ 
%   / _ \ | | | |\ \/ /| || || | / _` || '__|| | | | | |_  | | | || '_ \  / __|| __|| | / _ \ | '_ \ / __|
%  / ___ \| |_| | >  < | || || || (_| || |   | |_| | |  _| | |_| || | | || (__ | |_ | || (_) || | | |\__ \
% /_/   \_\\__,_|/_/\_\|_||_||_| \__,_||_|    \__, | |_|    \__,_||_| |_| \___| \__||_| \___/ |_| |_||___/
%                                             |___/       
% auxiliary functions




predicate link_difference(var 0..3: diff_pattern, var -2..15: diff_value) =  
    if (diff_pattern == 0) then diff_value == 0
    elseif (diff_pattern == 1) then diff_value > 0
    elseif (diff_pattern == 2) then diff_value == -1
    else diff_value = -2
    endif
;

predicate sbox(var 0..3: diff_in, var 0..3: diff_out) = 
    diff_out != 1 /\
    (diff_in + diff_out) in {0, 3, 4, 6} /\
    diff_out >= diff_in /\
    (diff_out - diff_in) <= 1
;

predicate xor_operation(var 0..3: diff_a, var -2..15: dvalue_a, 
                        var 0..3: diff_b, var -2..15: dvalue_b, 
                        var 0..3: diff_c, var -2..15: dvalue_c) = 
    if (diff_a + diff_b > 2) then 
        (diff_c = 3) /\ (dvalue_c = -2)
    elseif (diff_a + diff_b = 1) then
        (diff_c = 1) /\ (dvalue_c = dvalue_a + dvalue_b)
    elseif ((diff_a == 0) /\ (diff_b = 0)) then
        (diff_c = 0) /\ (dvalue_c = 0)
    elseif (dvalue_a + dvalue_b < 0) then
        (diff_c = 2) /\ (dvalue_c = -1)
    elseif (dvalue_a == dvalue_b) then
        (diff_c = 0) /\ (dvalue_c = 0)
    else
        (diff_c = 1) /\ 
        dvalue_c = (bool2int((dvalue_a mod 2) != (dvalue_b mod 2)) + 
        bool2int(((dvalue_a div 2) mod 2) != ((dvalue_b div 2) mod 2)) * 2 + 
        bool2int(((dvalue_a div 4) mod 2) != ((dvalue_b div 4) mod 2)) * 4 +
        bool2int(((dvalue_a div 8) mod 2) != ((dvalue_b div 8) mod 2)) * 8)
    endif
;

predicate mix_column_forward(var 0..3: diff_in1, var -2..15: dvalue_in1,
                             var 0..3: diff_in2, var -2..15: dvalue_in2,
                             var 0..3: diff_in3, var -2..15: dvalue_in3,
                             var 0..3: diff_in4, var -2..15: dvalue_in4,
                             var 0..3: diff_out1, var -2..15: dvalue_out1,
                             var 0..3: diff_out2, var -2..15: dvalue_out2,
                             var 0..3: diff_out3, var -2..15: dvalue_out3,
                             var 0..3: diff_out4, var -2..15: dvalue_out4) =
    % the second row
    diff_out2 = diff_in1 /\
    dvalue_out2 = dvalue_in1
    /\
    % the third row
    xor_operation(diff_in2, dvalue_in2, diff_in3, dvalue_in3, diff_out3, dvalue_out3)
    /\
    % the fourth row
    xor_operation(diff_in1, dvalue_in1, diff_in3, dvalue_in3, diff_out4, dvalue_out4)
    /\
    % the first row
    xor_operation(diff_out4, dvalue_out4, diff_in4, dvalue_in4, diff_out1, dvalue_out1)
;

predicate mix_column_backward(var 0..3: diff_in1, var -2..15: dvalue_in1,
                              var 0..3: diff_in2, var -2..15: dvalue_in2,
                              var 0..3: diff_in3, var -2..15: dvalue_in3,
                              var 0..3: diff_in4, var -2..15: dvalue_in4,
                              var 0..3: diff_out1, var -2..15: dvalue_out1,
                              var 0..3: diff_out2, var -2..15: dvalue_out2,
                              var 0..3: diff_out3, var -2..15: dvalue_out3,
                              var 0..3: diff_out4, var -2..15: dvalue_out4) =
    
    % the first row
    diff_out1 = diff_in2  /\
    dvalue_out1 = dvalue_in2
    /\
    % the thrid row
    xor_operation(diff_in2, dvalue_in2, diff_in4, dvalue_in4, diff_out3, dvalue_out3)
    /\
    % the fourth row
    xor_operation(diff_in1, dvalue_in1, diff_in4, dvalue_in4, diff_out4, dvalue_out4)
    /\
    % the second row
    xor_operation(diff_out3, dvalue_out3, diff_in3, dvalue_in3, diff_out2, dvalue_out2)
;
