// SPDX-License-Identifier: GPL-2.0
#ifndef __KSYMS_MODULE_UTIL_H__
#define __KSYMS_MODULE_UTIL_H__

#define __KFUNC_NR_EXP(Y)							\
Y(0) Y(1) Y(2) Y(3) Y(4) Y(5) Y(6) Y(7) Y(8) Y(9) Y(10) Y(11) Y(12)		\
Y(13) Y(14) Y(15) Y(16) Y(17) Y(18) Y(19) Y(20) Y(21) Y(22) Y(23)		\
Y(24) Y(25) Y(26) Y(27) Y(28) Y(29) Y(30) Y(31) Y(32) Y(33) Y(34)		\
Y(35) Y(36) Y(37) Y(38) Y(39) Y(40) Y(41) Y(42) Y(43) Y(44) Y(45)		\
Y(46) Y(47) Y(48) Y(49) Y(50) Y(51) Y(52) Y(53) Y(54) Y(55) Y(56)		\
Y(57) Y(58) Y(59) Y(60) Y(61) Y(62) Y(63) Y(64) Y(65) Y(66) Y(67)		\
Y(68) Y(69) Y(70) Y(71) Y(72) Y(73) Y(74) Y(75) Y(76) Y(77) Y(78)		\
Y(79) Y(80) Y(81) Y(82) Y(83) Y(84) Y(85) Y(86) Y(87) Y(88) Y(89)		\
Y(90) Y(91) Y(92) Y(93) Y(94) Y(95) Y(96) Y(97) Y(98) Y(99) Y(100)		\
Y(101) Y(102) Y(103) Y(104) Y(105) Y(106) Y(107) Y(108) Y(109) Y(110)		\
Y(111) Y(112) Y(113) Y(114) Y(115) Y(116) Y(117) Y(118) Y(119) Y(120)		\
Y(121) Y(122) Y(123) Y(124) Y(125) Y(126) Y(127) Y(128) Y(129) Y(130)		\
Y(131) Y(132) Y(133) Y(134) Y(135) Y(136) Y(137) Y(138) Y(139) Y(140)		\
Y(141) Y(142) Y(143) Y(144) Y(145) Y(146) Y(147) Y(148) Y(149) Y(150)		\
Y(151) Y(152) Y(153) Y(154) Y(155) Y(156) Y(157) Y(158) Y(159) Y(160)		\
Y(161) Y(162) Y(163) Y(164) Y(165) Y(166) Y(167) Y(168) Y(169) Y(170)		\
Y(171) Y(172) Y(173) Y(174) Y(175) Y(176) Y(177) Y(178) Y(179) Y(180)		\
Y(181) Y(182) Y(183) Y(184) Y(185) Y(186) Y(187) Y(188) Y(189) Y(190)		\
Y(191) Y(192) Y(193) Y(194) Y(195) Y(196) Y(197) Y(198) Y(199) Y(200)		\
Y(201) Y(202) Y(203) Y(204) Y(205) Y(206) Y(207) Y(208) Y(209) Y(210)		\
Y(211) Y(212) Y(213) Y(214) Y(215) Y(216) Y(217) Y(218) Y(219) Y(220)		\
Y(221) Y(222) Y(223) Y(224) Y(225) Y(226) Y(227) Y(228) Y(229) Y(230)		\
Y(231) Y(232) Y(233) Y(234) Y(235) Y(236) Y(237) Y(238) Y(239) Y(240)		\
Y(241) Y(242) Y(243) Y(244) Y(245) Y(246) Y(247) Y(248) Y(249) Y(250)		\
Y(251) Y(252) Y(253) Y(254) Y(255)

#define __KFUNC_A(nr) bpf_testmod_test_mod_kfunc_##nr();
#define KFUNC_VALID_DISTINCT_256 __KFUNC_NR_EXP(__KFUNC_A)

#define __KFUNC_B(nr) extern void bpf_testmod_test_mod_kfunc_##nr(void) __ksym;
#define KFUNC_KSYM_DECLARE_VALID_DISTINCT_256 __KFUNC_NR_EXP(__KFUNC_B)

#define __KFUNC_C(nr) noinline void bpf_testmod_test_mod_kfunc_##nr(void) {};
#define KFUNC_DEFINE_VALID_DISTINCT_256 __KFUNC_NR_EXP(__KFUNC_C)

#define __KFUNC_D(nr) BTF_ID(func, bpf_testmod_test_mod_kfunc_##nr)
#define KFUNC_BTF_ID_VALID_DISTINCT_256 __KFUNC_NR_EXP(__KFUNC_D)

#define __KFUNC_E(nr) bpf_testmod_test_mod_kfunc(nr);
#define KFUNC_VALID_SAME_ONE __KFUNC_E(0)
#define KFUNC_VALID_SAME_256 __KFUNC_NR_EXP(__KFUNC_E)

#endif
