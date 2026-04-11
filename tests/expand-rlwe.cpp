#include "core/include/rgsw.h"
#include "core/include/helpers.h"
#include "openfhe.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>


using namespace lbcrypto;

template <typename T>
inline void PrintRGSW(const CryptoContext<T>& cc, KeyPair<T> keys, const std::vector<Ciphertext<T>>& vec, size_t columns) {
    Plaintext plaintext;
    for(const auto &c : vec) {
        cc->Decrypt(keys.secretKey, c, &plaintext);
        plaintext->SetLength(columns);
        std::cout << plaintext << std::endl;
    }
}

/**
 * @file tests/expand-rlwe.cpp
 * @brief Test ExpandRLWE functon
 * 
 * Should take an RLWE packed ciphertext with n slots and output 
 * n RLWE ciphertexts, each encrypting one slot
 */
int main() {

    const auto index = std::vector<int64_t>{ 1, 1, 0, 1 };

    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels
    const uint32_t N = 16384;        // Smallest recommended value with BGN-rns (l = 3)?

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2*log_n - 1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

    Server::ExtendedCryptoContext<DCRTPoly> cc = Server::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Created context" << std::endl;

    // encrypt a sample plaintext
    Plaintext plaintext = cc->MakePackedPlaintext({1, 1, 0, 1});
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    // rotations used are [1, n)
    auto rotations = { 0, 1, 2, 3 };
    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    
    auto rgswCiphertext = core::server::HoistedExpandRLWE(cc, ciphertext, 4, keyPair.publicKey);
    
    std::cout << "Expanded RLWE" << std::endl;

    // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    PrintRGSW(cc, keyPair, rgswCiphertext, n);

    // TODO: Assert correctness

    return 0;
}
