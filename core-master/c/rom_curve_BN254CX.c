/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "arch.h"
#include "ecp_BN254CX.h"

/* Curve BN254CX - Pairing friendly BN curve */

/* CertiVox BN curve/field  */


#if CHUNK==16

const int CURVE_Cof_I_BN254CX= 1;
const int CURVE_B_I_BN254CX= 2;
const BIG_256_13 CURVE_B_BN254CX= {0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_13 CURVE_Order_BN254CX= {0x1F6D,0x1758,0x98D,0x381,0xBE1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48};
const BIG_256_13 CURVE_Gx_BN254CX= {0x15B2,0xDA,0x1BD7,0xC47,0x1BE6,0x1F70,0x24,0x1DC3,0x1FD6,0x1921,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48};
const BIG_256_13 CURVE_Gy_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_13 CURVE_HTPC_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_13 CURVE_Bnx_BN254CX= {0x12B1,0x1E00,0x0,0x0,0x400,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_13 CURVE_Cof_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

const BIG_256_13 CURVE_Pxa_BN254CX= {0xC74,0x697,0x1BB9,0xA39,0xC08,0x1393,0xF8,0x17F4,0x1C85,0x1C83,0x12EE,0xB86,0x100F,0x592,0x18D6,0x164A,0x1053,0x963,0x1A0B,0x32};
const BIG_256_13 CURVE_Pxb_BN254CX= {0xFE1,0x114E,0x2CB,0xB1D,0x147A,0x187,0x827,0x1618,0x1B97,0x1FC0,0x5D0,0x11D3,0x137A,0x8E4,0xA80,0x1EC9,0x1E19,0xF61,0x19AE,0x28};
const BIG_256_13 CURVE_Pya_BN254CX= {0x9F,0x185F,0x1AF3,0x17F9,0x10CF,0xD9,0x11FB,0x7B0,0x1B3,0xB1B,0x1882,0x1B5D,0x157,0xF11,0x1760,0x571,0x1233,0xECB,0x1E7B,0x14};
const BIG_256_13 CURVE_Pyb_BN254CX= {0xE9D,0x4C7,0x8A2,0x96,0x1ED9,0x16F5,0x74B,0x14AD,0x64E,0xE14,0xD18,0x1B1A,0x512,0x372,0xD7,0x1812,0xCC4,0x1CF,0x583,0xC};

const BIG_256_13 CURVE_W_BN254CX[2]= {{0xB83,0x117F,0x1245,0x8C6,0x5,0x1C09,0xD00,0x1,0x0,0x300,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}};
const BIG_256_13 CURVE_SB_BN254CX[2][2]= {{{0x10E4,0xD80,0x1247,0x8C6,0x805,0x1C09,0xD00,0x1,0x0,0x300,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x13EA,0x5D9,0x1748,0x1ABA,0xBDB,0x75E,0x623,0x1DC0,0x1FD6,0x1321,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48}}};
const BIG_256_13 CURVE_WB_BN254CX[4]= {{0x4B0,0x13D4,0x615,0x1842,0x401,0x958,0xF00,0x0,0x0,0x100,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x475,0x1110,0x56F,0x1BF3,0x36C,0x1FCD,0x329,0x1DB5,0x1E94,0xE03,0xA83,0x10E0,0x0,0x0,0xC0,0x0,0x0,0x0,0x0,0x0},{0xB93,0x788,0x12B8,0xDF9,0x13B6,0x1FE6,0x1194,0xEDA,0x1F4A,0x1701,0x541,0x870,0x0,0x0,0x60,0x0,0x0,0x0,0x0,0x0},{0xA11,0xFD5,0x617,0x1842,0xC01,0x958,0xF00,0x0,0x0,0x100,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}};
const BIG_256_13 CURVE_BB_BN254CX[4][4]= {{{0xCBD,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0xCBC,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0xCBC,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0x562,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0xCBC,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0xCBD,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0xCBC,0x1958,0x98C,0x381,0x7E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48}},{{0x562,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x561,0x1C01,0x1,0x0,0x800,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x12B2,0x1E00,0x0,0x0,0x400,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0xAC2,0x1802,0x3,0x0,0x1000,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x1A0A,0x1B57,0x98B,0x381,0x3E1,0x367,0x1324,0x1DC1,0x1FD6,0x1621,0x19B4,0x14C6,0x1647,0x1EEF,0x16C2,0x541,0x870,0x0,0x0,0x48},{0x12B2,0x1E00,0x0,0x0,0x400,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}}};
#endif

#if CHUNK==32

const int CURVE_Cof_I_BN254CX= 1;
const int CURVE_B_I_BN254CX= 2;
const BIG_256_28 CURVE_B_BN254CX= {0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_28 CURVE_Order_BN254CX= {0x6EB1F6D,0x11C0A63,0x906CEBE,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2};
const BIG_256_28 CURVE_Gx_BN254CX= {0xC1B55B2,0x6623EF5,0x93EE1BE,0xD6EE180,0x6D3243F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2};
const BIG_256_28 CURVE_Gy_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_28 CURVE_HTPC_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_28 CURVE_Bnx_BN254CX= {0x3C012B1,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const BIG_256_28 CURVE_Cof_BN254CX= {0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

const BIG_256_28 CURVE_Pxa_BN254CX= {0x4D2EC74,0x851CEEE,0xE2726C0,0x85BFA03,0xBBB907C,0xF5C34,0x6358B25,0x7053B25,0x9682D2C,0x1};
const BIG_256_28 CURVE_Pxb_BN254CX= {0xE29CFE1,0xA58E8B2,0x9C30F47,0x97B0C20,0x743F81B,0x37A8E99,0xAA011C9,0x3E19F64,0x466B9EC,0x1};
const BIG_256_28 CURVE_Pya_BN254CX= {0xF0BE09F,0xFBFCEBC,0xEC1B30C,0xB33D847,0x2096361,0x157DAEE,0xDD81E22,0x72332B8,0xA79EDD9,0x0};
const BIG_256_28 CURVE_Pyb_BN254CX= {0x898EE9D,0x904B228,0x2EDEBED,0x4EA569D,0x461C286,0x512D8D3,0x35C6E4,0xECC4C09,0x6160C39,0x0};


const BIG_256_28 CURVE_W_BN254CX[2]= {{0x62FEB83,0x5463491,0x381200,0xB4,0x6000,0x0,0x0,0x0,0x0,0x0},{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0}};
const BIG_256_28 CURVE_SB_BN254CX[2][2]= {{{0xDB010E4,0x5463491,0x381280,0xB4,0x6000,0x0,0x0,0x0,0x0,0x0},{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0xBB33EA,0xBD5D5D2,0x8CEBCBD,0xD6EE018,0x6D2643F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2}}};
const BIG_256_28 CURVE_WB_BN254CX[4]= {{0x67A84B0,0x1C21185,0x12B040,0x3C,0x2000,0x0,0x0,0x0,0x0,0x0},{0xE220475,0xCDF995B,0xA7F9A36,0x94EDA8C,0xA0DC07E,0x8702,0x300000,0x0,0x0,0x0},{0xF10B93,0x66FCCAE,0x53FCD3B,0x4A76D46,0x506E03F,0x4381,0x180000,0x0,0x0,0x0},{0xDFAAA11,0x1C21185,0x12B0C0,0x3C,0x2000,0x0,0x0,0x0,0x0,0x0}};
const BIG_256_28 CURVE_BB_BN254CX[4][4]= {{{0x32B0CBD,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x32B0CBC,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x32B0CBC,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x7802562,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x32B0CBC,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x32B0CBD,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x32B0CBC,0x11C0A63,0x906CE7E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2}},{{0x7802562,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0x7802561,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0}},{{0x3C012B2,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0xF004AC2,0x0,0x100,0x0,0x0,0x0,0x0,0x0,0x0,0x0},{0xF6AFA0A,0x11C0A62,0x906CE3E,0xD6EE0CC,0x6D2C43F,0x647A636,0xDB0BDDF,0x8702A0,0x4000000,0x2},{0x3C012B2,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0}}};
#endif

#if CHUNK==64

const int CURVE_Cof_I_BN254CX= 1;
const int CURVE_B_I_BN254CX= 2;
const BIG_256_56 CURVE_B_BN254CX= {0x2L,0x0L,0x0L,0x0L,0x0L};
const BIG_256_56 CURVE_Order_BN254CX= {0x11C0A636EB1F6DL,0xD6EE0CC906CEBEL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L};
const BIG_256_56 CURVE_Gx_BN254CX= {0x6623EF5C1B55B2L,0xD6EE18093EE1BEL,0x647A6366D3243FL,0x8702A0DB0BDDFL,0x24000000L};
const BIG_256_56 CURVE_Gy_BN254CX= {0x1L,0x0L,0x0L,0x0L,0x0L};
const BIG_256_56 CURVE_HTPC_BN254CX= {0x1L,0x0L,0x0L,0x0L,0x0L};
const BIG_256_56 CURVE_Bnx_BN254CX= {0x3C012B1L,0x40L,0x0L,0x0L,0x0L};
const BIG_256_56 CURVE_Cof_BN254CX= {0x1L,0x0L,0x0L,0x0L,0x0L};

const BIG_256_56 CURVE_Pxa_BN254CX= {0x851CEEE4D2EC74L,0x85BFA03E2726C0L,0xF5C34BBB907CL,0x7053B256358B25L,0x19682D2CL};
const BIG_256_56 CURVE_Pxb_BN254CX= {0xA58E8B2E29CFE1L,0x97B0C209C30F47L,0x37A8E99743F81BL,0x3E19F64AA011C9L,0x1466B9ECL};
const BIG_256_56 CURVE_Pya_BN254CX= {0xFBFCEBCF0BE09FL,0xB33D847EC1B30CL,0x157DAEE2096361L,0x72332B8DD81E22L,0xA79EDD9L};
const BIG_256_56 CURVE_Pyb_BN254CX= {0x904B228898EE9DL,0x4EA569D2EDEBEDL,0x512D8D3461C286L,0xECC4C09035C6E4L,0x6160C39L};


const BIG_256_56 CURVE_W_BN254CX[2]= {{0x546349162FEB83L,0xB40381200L,0x6000L,0x0L,0x0L},{0x7802561L,0x80L,0x0L,0x0L,0x0L}};
const BIG_256_56 CURVE_SB_BN254CX[2][2]= {{{0x5463491DB010E4L,0xB40381280L,0x6000L,0x0L,0x0L},{0x7802561L,0x80L,0x0L,0x0L,0x0L}},{{0x7802561L,0x80L,0x0L,0x0L,0x0L},{0xBD5D5D20BB33EAL,0xD6EE0188CEBCBDL,0x647A6366D2643FL,0x8702A0DB0BDDFL,0x24000000L}}};
const BIG_256_56 CURVE_WB_BN254CX[4]= {{0x1C2118567A84B0L,0x3C012B040L,0x2000L,0x0L,0x0L},{0xCDF995BE220475L,0x94EDA8CA7F9A36L,0x8702A0DC07EL,0x300000L,0x0L},{0x66FCCAE0F10B93L,0x4A76D4653FCD3BL,0x4381506E03FL,0x180000L,0x0L},{0x1C21185DFAAA11L,0x3C012B0C0L,0x2000L,0x0L,0x0L}};
const BIG_256_56 CURVE_BB_BN254CX[4][4]= {{{0x11C0A6332B0CBDL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x11C0A6332B0CBCL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x11C0A6332B0CBCL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x7802562L,0x80L,0x0L,0x0L,0x0L}},{{0x7802561L,0x80L,0x0L,0x0L,0x0L},{0x11C0A6332B0CBCL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x11C0A6332B0CBDL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x11C0A6332B0CBCL,0xD6EE0CC906CE7EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L}},{{0x7802562L,0x80L,0x0L,0x0L,0x0L},{0x7802561L,0x80L,0x0L,0x0L,0x0L},{0x7802561L,0x80L,0x0L,0x0L,0x0L},{0x7802561L,0x80L,0x0L,0x0L,0x0L}},{{0x3C012B2L,0x40L,0x0L,0x0L,0x0L},{0xF004AC2L,0x100L,0x0L,0x0L,0x0L},{0x11C0A62F6AFA0AL,0xD6EE0CC906CE3EL,0x647A6366D2C43FL,0x8702A0DB0BDDFL,0x24000000L},{0x3C012B2L,0x40L,0x0L,0x0L,0x0L}}};
#endif
