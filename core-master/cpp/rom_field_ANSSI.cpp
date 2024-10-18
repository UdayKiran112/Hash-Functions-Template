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
#include "fp_ANSSI.h"

namespace ANSSI {

/* ANNSI Curve */

#if CHUNK==16

#error Not supported

#endif

#if CHUNK==32

using namespace B256_28;

// Base Bits= 28
const BIG Modulus= {0x86E9C03,0xFCF353D,0x8CA6DE8,0xADBCABC,0x35B3961,0xE8CE424,0xF10126D,0xB3AD58,0x1FD178C,0xF};
const BIG ROI= {0x86E9C02,0xFCF353D,0x8CA6DE8,0xADBCABC,0x35B3961,0xE8CE424,0xF10126D,0xB3AD58,0x1FD178C,0xF};
const BIG R2modp= {0x288CC9C,0x18D2374,0x646BD2B,0x4929E67,0xD6F7F2D,0x220E6C1,0xABCE02E,0x751B1FD,0x7401B78,0xE};
const chunk MConst= 0x64E1155;
#endif

#if CHUNK==64

using namespace B256_56;

// Base Bits= 56
const BIG Modulus= {0xFCF353D86E9C03L,0xADBCABC8CA6DE8L,0xE8CE42435B3961L,0xB3AD58F10126DL,0xF1FD178CL};
const BIG ROI= {0xFCF353D86E9C02L,0xADBCABC8CA6DE8L,0xE8CE42435B3961L,0xB3AD58F10126DL,0xF1FD178CL};
const BIG R2modp= {0x18D2374288CC9CL,0x4929E67646BD2BL,0x220E6C1D6F7F2DL,0x751B1FDABCE02EL,0xE7401B78L};
const chunk MConst= 0x97483A164E1155L;
#endif

}
