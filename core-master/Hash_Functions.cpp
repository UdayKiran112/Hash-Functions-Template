#include <bits/stdc++.h>
#include "cpp/core.h"
#include "cpp/eddsa_SECP256K1.h"
#include "cpp/config_big_B256_56.h"
#include "cpp/randapi.h"
#include "cpp/arch.h"
#include "cpp/ecdh_SECP256K1.h"
#include "cpp/ecp_SECP256K1.h"
#include "cpp/big_B256_56.h"

using namespace std;
using namespace B256_56;
using namespace SECP256K1;

// set generator Point
void setGeneratorPoint(SECP256K1::ECP *G)
{
    using namespace SECP256K1;
    ECP P;
    bool gen = ECP_generator(&P);
    if (gen == 0)
    {
        throw invalid_argument("Failed to generate generator point");
    }

    if (ECP_isinf(&P) == 1)
    {
        throw runtime_error("Generator point is infinity");
    }
    else
    {
        ECP_copy(G, &P);
    }
}

// Function to concatenate two octets without truncation
void concat_octets(octet *output, octet *octet1, octet *octet2)
{
    // Calculate the total length of the concatenated octet
    int total_length = octet1->len + octet2->len;

    // Allocate memory for the new concatenated value
    output->val = (char *)malloc(total_length);
    output->max = total_length;
    output->len = total_length;

    // Copy data from the first octet into the output
    memcpy(output->val, octet1->val, octet1->len);

    // Copy data from the second octet into the output (after the first)
    memcpy(output->val + octet1->len, octet2->val, octet2->len);
}

// Hash function-0:------>h0:{0,1}*---->Zq*
void hash_0(int hlen, octet *input, octet *output)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, input);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);
}

// Hash function-1:------>h1:{0,1}* x G^2 -------->Zq*
void hash_1(int hlen, octet *input, octet *output, octet *group_1, octet *group_2)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // concatenate the input octets
    octet temp1, temp2;

    concat_octets(&temp1, group_1, group_2);
    concat_octets(&temp2, input, &temp1);

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, &temp2);

    if (H.len != hlen)
    {
        cout << "Hash length mismatch: Expected " << hlen << " but got " << H.len << endl;
    }

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);

    free(temp1.val);
    free(temp2.val);
}

// Hash function-2:------>h2:{0,1}* x G^3 -------->Zq*
void hash_2(int hlen, octet *input, octet *output, octet *group_1, octet *group_2, octet *group_3)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // concatenate the input octets
    octet temp1, temp2, temp3;
    concat_octets(&temp1, group_2, group_3);
    concat_octets(&temp2, group_1, &temp1);
    concat_octets(&temp3, input, &temp2);

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, &temp3);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);

    free(temp1.val);
    free(temp2.val);
    free(temp3.val);
}

// Hash function-3:------>h3:{0,1}* x G^4 -------->Zq*
void hash_3(int hlen, octet *input, octet *output, octet *group_1, octet *group_2, octet *group_3, octet *group_4)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // concatenate the input octets
    octet temp1, temp2, temp3, temp4;
    concat_octets(&temp1, group_3, group_4);
    concat_octets(&temp2, group_2, &temp1);
    concat_octets(&temp3, group_1, &temp2);
    concat_octets(&temp4, input, &temp3);

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, &temp4);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);

    free(temp1.val);
    free(temp2.val);
    free(temp3.val);
    free(temp4.val);
}

// Hash function-4:------>h4:{0,1}* x {0,1}* x G x {0,1}* -------->Zq*
void hash_4(int hlen, octet *input_1, octet *input_2, octet *group, octet *input_3, octet *output)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // concatenate the input octets
    octet temp1, temp2, temp3;
    concat_octets(&temp1, group, input_3);
    concat_octets(&temp2, input_2, &temp1);
    concat_octets(&temp3, input_1, &temp2);

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, &temp3);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);

    free(temp1.val);
    free(temp2.val);
    free(temp3.val);
}

int main()
{
    // Random number generator
    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;

    // Improve seed generation by combining time and random_device
    std::random_device rd;
    ran = static_cast<unsigned long>(time(nullptr)) ^ rd();

    // Populate RAW with random data
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;

    // Fill the rest of RAW with high-entropy data
    for (int i = 4; i < 100; i++)
    {
        RAW.val[i] = rd() & 0xFF; // Use random_device to fill the remaining bytes
    }

    // Initialize CSPRNG
    core::CREATE_CSPRNG(&RNG, &RAW);

    // set generator point
    ECP G;
    setGeneratorPoint(&G);

    // Initialise a random numbers x and r
    char priv[EGS_SECP256K1];
    octet x_oct = {0, sizeof(priv), priv};
    octet r_oct = {0, sizeof(priv), priv};

    BIG x, r, order;
    BIG_rcopy(order, CURVE_Order);

    cout << "Order of the curve: ";
    BIG_output(order);
    cout << endl;

    BIG_randomnum(x, order, &RNG);
    BIG_randomnum(r, order, &RNG);
    BIG_toBytes(x_oct.val, x);
    BIG_toBytes(r_oct.val, r);

    cout << "x: ";
    BIG_output(x);
    cout << endl
         << endl;

    cout << "r: ";
    BIG_output(r);
    cout << endl
         << endl;

    // generate GK from x and A from r ==> GK = x.G && A = r.G
    ECP GK, A;
    ECP_copy(&GK, &G);
    ECP_copy(&A, &G);
    ECP_clmul(&GK, x, order);
    ECP_clmul(&A, r, order);

    cout << "GK: ";
    ECP_output(&GK);
    cout << endl;

    cout << "A: ";
    ECP_output(&A);
    cout << endl;

    // convert A and GK to octets
    char field[2 * EFS_SECP256K1 + 1];
    octet A_oct = {0, sizeof(field), field};
    octet GK_oct = {0, sizeof(field), field};

    ECP_toOctet(&A_oct, &A, false);
    ECP_toOctet(&GK_oct, &GK, false);

    // generate random private key and public key--> private key and PK
    char priv_key[EGS_SECP256K1];
    char pub_key[2 * EFS_SECP256K1 + 1];

    octet priv_key_oct = {0, sizeof(priv_key), priv_key};
    octet pub_key_oct = {0, sizeof(pub_key), pub_key};

    BIG priv_key_main;
    BIG_randomnum(priv_key_main, order, &RNG);
    BIG_toBytes(priv_key_oct.val, priv_key_main);

    ECP pub_key_main;
    ECP_copy(&pub_key_main, &G);
    ECP_clmul(&pub_key_main, priv_key_main, order);

    ECP_toOctet(&pub_key_oct, &pub_key_main, false);

    // print the public key
    cout << "Public key PK : ";
    ECP_output(&pub_key_main);
    cout << endl;

    string msg = "Hello World";
    octet message;
    message.len = msg.size();
    message.max = msg.size();
    message.val = new char[msg.size()];
    memcpy(message.val, msg.c_str(), msg.size());

    // Hash value calculation
    octet hash_val;
    hash_val.len = HASH_TYPE_SECP256K1;
    hash_val.max = HASH_TYPE_SECP256K1;
    hash_val.val = new char[HASH_TYPE_SECP256K1];

    // perform hash and assign that value to hash_val
    hash_1(HASH_TYPE_SECP256K1, &message, &hash_val, &pub_key_oct, &A_oct);

    // print the hash value
    cout << "Hash value: ";
    OCT_output(&hash_val);
    cout << endl;

    // perform x *hash_val = delta
    BIG del, hval;
    BIG_fromBytes(hval, hash_val.val);
    BIG_modmul(del, x, hval, order);

    cout << "Delta: ";
    BIG_output(del);
    cout << endl
         << endl;

    // LHS POint calculation
    ECP lhs;
    ECP_copy(&lhs, &G);
    ECP_mul(&lhs, del);

    cout << "Point LHS: ";
    ECP_output(&lhs);
    cout << endl;

    // perform GK * hash_val= pnt
    ECP pnt;
    ECP_copy(&pnt, &GK);
    ECP_mul(&pnt, hval);

    cout << "Point RHS: ";
    ECP_output(&pnt);
    cout << endl;

    if (ECP_equals(&lhs, &pnt))
    {
        cout << "Points are equal" << endl;
    }
    else
    {
        cout << "Points are not equal" << endl;
    }

    // Clean up the CSPRNG
    core::KILL_CSPRNG(&RNG);

    return 0;
}