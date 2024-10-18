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
#include "fp_BLS12443.h"

/* Curve BLS12443 - Pairing friendly BLS curve */

#if CHUNK==16

#error Not supported

#endif

#if CHUNK==32
// Base Bits= 29
const BIG_448_29 Modulus_BLS12443= {0x10AAAAAB,0x1FD55555,0x1921AAFF,0xA59AAAA,0x1424ABF7,0x19024801,0x1C42D855,0x96E429D,0x5119FF1,0x7855CAF,0x1020B3B1,0x4B6ABA4,0x92300A8,0x1054E434,0x1694F72C,0xAE};
const BIG_448_29 R2modp_BLS12443= {0x1118A8F7,0x1AB7CA8,0x2333712,0x132DCAD3,0x16E13882,0x10A03200,0x5B25363,0x9C87B7C,0xB9A40C9,0x975222C,0x28F658F,0x147AD511,0xF6028F0,0xBA52E95,0x262ED53,0x69};
const BIG_448_29 ROI_BLS12443= {0x10AAAAAA,0x1FD55555,0x1921AAFF,0xA59AAAA,0x1424ABF7,0x19024801,0x1C42D855,0x96E429D,0x5119FF1,0x7855CAF,0x1020B3B1,0x4B6ABA4,0x92300A8,0x1054E434,0x1694F72C,0xAE};
const BIG_448_29 SQRTm3_BLS12443= {0x14AAAAA8,0x1ED55556,0x16F7ACFF,0x6B6AA9,0x1E4D5046,0x1413E017,0x19DD9B9D,0x1E5F53AC,0x64B9158,0x1368614B,0x1F58A387,0x96E1519,0x8A07BAD,0x1054E434,0x1694F72C,0xAE};
const BIG_448_29 CRu_BLS12443= {0x2AAAAA9,0x1F555556,0x80CABFF,0x15628AAA,0x1938FE1E,0x168B140C,0xB1039F9,0x3E6CB25,0x5AE98A5,0xD76DEFD,0x7BCAB9C,0x1712605F,0x8E1BE2A,0x1054E434,0x1694F72C,0xAE};
const chunk MConst_BLS12443= 0x15FFFFFD;
const BIG_448_29 Fra_BLS12443= {0x49551C8,0x9D8A27E,0x1FACD18F,0x10236D5E,0x1D38DC4B,0xA2FCECB,0x46BF1F0,0x1C2F955E,0x1029E275,0x7D8436E,0x13DD8C0,0x1C9052A0,0x1979B8C6,0x1F97223F,0xC24C77,0x88};
const BIG_448_29 Frb_BLS12443= {0xC1558E3,0x15FCB2D7,0x1974D970,0x1A363D4B,0x16EBCFAB,0xED27935,0x17D6E665,0xD3EAD3F,0x14E7BD7B,0x1FAD1940,0xEE2DAF0,0x8265904,0xFA947E1,0x10BDC1F4,0x15D2AAB4,0x26};

#endif

#if CHUNK==64
// Base Bits= 60
const BIG_448_60 Modulus_BLS12443= {0xFFAAAAAB0AAAAABL,0x752CD5556486ABFL,0x572049003424ABFL,0xF14B7214EF10B61L,0xEC4F0AB95E5119FL,0xA825B55D24082CL,0xDCB20A9C8689230L,0x575A53L};
const BIG_448_60 R2modp_BLS12443= {0xF5CDA0EB0AD64E2L,0xDE66AA74FAE046BL,0x8B9229B598075AEL,0xDFAFBC5DB0E321EL,0x9AF61017ADA96A8L,0xFFAEA657DE81FE0L,0x1800170F84B9395L,0x8E3DDL};
const BIG_448_60 ROI_BLS12443= {0xFFAAAAAB0AAAAAAL,0x752CD5556486ABFL,0x572049003424ABFL,0xF14B7214EF10B61L,0xEC4F0AB95E5119FL,0xA825B55D24082CL,0xDCB20A9C8689230L,0x575A53L};
const BIG_448_60 SQRTm3_BLS12443= {0xFDAAAAAD4AAAAA8L,0x6035B554DBDEB3FL,0x76827C02FE4D504L,0x58F2FA9D667766EL,0xE1E6D0C29664B91L,0xBAD4B70A8CFD628L,0xDCB20A9C8688A07L,0x575A53L};
const BIG_448_60 CRu_BLS12443= {0xFEAAAAAC2AAAAA9L,0xEAB145552032AFFL,0xE6D162819938FE1L,0xA51F36592AC40E7L,0xE71AEDBDFA5AE98L,0xE2AB89302F9EF2AL,0xDCB20A9C8688E1BL,0x575A53L};
const chunk MConst_BLS12443= 0xC04000035FFFFFDL;
const BIG_448_60 Fra_BLS12443= {0xD3B144FC49551C8L,0xB811B6AF7EB3463L,0xC145F9D97D38DC4L,0x75E17CAAF11AFC7L,0x300FB086DD029E2L,0x8C6E48295004F76L,0x31DFF2E447F979BL,0x440309L};
const BIG_448_60 Frb_BLS12443= {0x2BF965AEC1558E3L,0xBD1B1EA5E5D365CL,0x95DA4F26B6EBCFAL,0x7B69F569FDF5B99L,0xBC3F5A32814E7BDL,0x7E14132C823B8B6L,0xAAD217B83E8FA94L,0x13574AL};

#endif