
# Cryptographic Implementation using SECP256K1

## Overview
This project is a cryptographic implementation utilizing the SECP256K1 elliptic curve. It includes the generation of private and public keys, hashing functions, point multiplication, and verification of points on the elliptic curve.

## Prerequisites
- C++ Compiler supporting C++11 or later (e.g., g++)
- Required libraries:
  - `cpp/core.h`
  - `cpp/eddsa_SECP256K1.h`
  - `cpp/config_big_B256_56.h`
  - `cpp/randapi.h`
  - `cpp/arch.h`
  - `cpp/ecdh_SECP256K1.h`
  - `cpp/ecp_SECP256K1.h`
  - `cpp/big_B256_56.h`

## Key Functionalities
1. **Elliptic Curve Point Generation**: 
   - `setGeneratorPoint()` sets the generator point for the SECP256K1 curve.
   
2. **Concatenation of Octets**:
   - `concat_octets()` is used to concatenate two octets into one without truncation.

3. **Hash Functions**:
   - `hash_0`: Hashes an input octet to a target hash length.
   - `hash_1`: Hashes an input combined with two elliptic curve points to the specified hash length.
   - `hash_2`: Hashes an input combined with three elliptic curve points.
   - `hash_3`: Hashes an input combined with four elliptic curve points.
   - `hash_5`: Hashes an input combined with an elliptic curve point and two other inputs.

4. **Random Number Generation**:
   - Uses CSPRNG (`csprng`) for generating random numbers, which are used for creating private keys and other random values.

5. **Elliptic Curve Point Multiplication**:
   - Performs scalar multiplication on elliptic curve points, including operations like `GK = x.G` and `A = r.G`.

6. **Public Key Generation**:
   - Generates a public key from a randomly generated private key using the SECP256K1 generator point.

7. **Hash Value Calculation**:
   - Computes a hash value for a given message string, which is later used in calculations involving elliptic curve points.

8. **Point Comparison**:
   - Verifies whether two elliptic curve points (lhs and rhs) are equivalent, demonstrating the correctness of the operations.

## Example
The `main()` function showcases the full process:
1. Initializes a CSPRNG.
2. Sets the generator point for the SECP256K1 curve.
3. Generates random private keys (`x` and `r`) and computes their corresponding points (`GK` and `A`).
4. Computes the public key (`PK`) using another private key.
5. Calculates the hash value of a message using `hash_1`.
6. Performs operations involving scalar multiplication and verifies point equality on the elliptic curve.

## Usage
Compile the code using the Makefile:
```
make
```
Run the executable:
```
./main
```

## Output
The program displays:
- The order of the elliptic curve.
- The random values `x` and `r`.
- Generated points `GK` and `A`.
- The computed hash value.
- The delta value (`x * hash_val`).
- The computed points `lhs` and `rhs`.
- Whether the points `lhs` and `rhs` are equal.

## Notes
- Ensure that all required libraries and headers are correctly included.
- The random number generation is seeded using a combination of system time and `std::random_device` for higher entropy.
- Proper memory management is implemented for octet handling, with `malloc` and `free` used for dynamic memory management.

## License
This project is provided under the MIT License. See the `LICENSE` file for more details.

## Acknowledgments
- Uses the SECP256K1 curve from `cpp/eddsa_SECP256K1.h` for elliptic curve operations.
- Based on the [AMCL](https://github.com/miracl/amcl) cryptographic library for C++.