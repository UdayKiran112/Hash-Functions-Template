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

/* Fixed Data in ROM - Field and Curve parameters */


package org.miracl.core.BN158;

public class ROM
{

public static final int[] Modulus= {0xB04E013,0x72280A,0xFD3FB95,0x9953CF6,0x27628C,0x24012};
public static final int[] R2modp= {0x545973D,0xA60739B,0x65DB288,0x526165,0xB226C,0x17315};
public static final int[] ROI= {0xB04E012,0x72280A,0xFD3FB95,0x9953CF6,0x27628C,0x24012};
public static final int[] SQRTm3= {0x8018004,0x7F0E404,0x99F4CE2,0x95F35CA,0x2761FC,0x24012};
public static final int[] CRu= {0x181B007,0x440A203,0x31A5759,0x1B0396,0x48,0x0};
public static final int MConst= 0x4F615E5;
public static final int[] Fra= {0x6ECE2A9,0xA167429,0x99296F2,0xE1BF21C,0xCF82A02,0xA85E};
public static final int[] Frb= {0x417FD6A,0x65BB3E1,0x64164A2,0xB794ADA,0x32F3889,0x197B3};

public static final int CURVE_Cof_I= 1;
public static final int[] CURVE_Cof= {0x1,0x0,0x0,0x0,0x0,0x0};
public static final int CURVE_B_I= 5;
public static final int[] CURVE_B= {0x5,0x0,0x0,0x0,0x0,0x0};
public static final int[] CURVE_Order= {0xF04200D,0xD59F209,0xF73FA14,0x9953CF6,0x27628C,0x24012};
public static final int[] CURVE_Gx= {0xB04E012,0x72280A,0xFD3FB95,0x9953CF6,0x27628C,0x24012};
public static final int[] CURVE_Gy= {0x2,0x0,0x0,0x0,0x0,0x0};
public static final int[] CURVE_HTPC= {0x1,0x0,0x0,0x0,0x0,0x0};

public static final int[] CURVE_Bnx= {0x801001,0x400,0x0,0x0,0x0,0x0};
public static final int[] CURVE_Pxa= {0x33A5768,0x3B27650,0x3022922,0x1EECE2B,0xF882728,0x1EA35};
public static final int[] CURVE_Pxb= {0x776A2F5,0x7B04ACE,0x14F9D68,0x5D05BA3,0x611EB92,0x23485};
public static final int[] CURVE_Pya= {0x30CFE24,0x69AB26E,0xF92C435,0x1FB7A85,0xF906B6E,0x1C952};
public static final int[] CURVE_Pyb= {0x8E8609D,0x9101773,0xA0F3EE2,0x8445B3B,0x9544ED8,0x23E28};
public static final int[][] CURVE_W= {{0xA008003,0x3182600,0x600180,0x0,0x0,0x0},{0x1002001,0x800,0x0,0x0,0x0,0x0}};
public static final int[][][] CURVE_SB= {{{0xB00A004,0x3182E00,0x600180,0x0,0x0,0x0},{0x1002001,0x800,0x0,0x0,0x0,0x0}},{{0x1002001,0x800,0x0,0x0,0x0,0x0},{0x503A00A,0xA41CC09,0xF13F894,0x9953CF6,0x27628C,0x24012}}};
public static final int[][] CURVE_WB= {{0x2801000,0x1080600,0x200080,0x0,0x0,0x0},{0x6815005,0xF907C02,0x2519090,0x120264,0x30,0x0},{0x380B003,0x7C84001,0x128C848,0x90132,0x18,0x0},{0x3803001,0x1080E00,0x200080,0x0,0x0,0x0}};
public static final int[][][] CURVE_BB= {{{0xE84100D,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0xE84100C,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0xE84100C,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0x1002002,0x800,0x0,0x0,0x0,0x0}},{{0x1002001,0x800,0x0,0x0,0x0,0x0},{0xE84100C,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0xE84100D,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0xE84100C,0xD59EE09,0xF73FA14,0x9953CF6,0x27628C,0x24012}},{{0x1002002,0x800,0x0,0x0,0x0,0x0},{0x1002001,0x800,0x0,0x0,0x0,0x0},{0x1002001,0x800,0x0,0x0,0x0,0x0},{0x1002001,0x800,0x0,0x0,0x0,0x0}},{{0x801002,0x400,0x0,0x0,0x0,0x0},{0x2004002,0x1000,0x0,0x0,0x0,0x0},{0xE04000A,0xD59EA09,0xF73FA14,0x9953CF6,0x27628C,0x24012},{0x801002,0x400,0x0,0x0,0x0,0x0}}};

}
