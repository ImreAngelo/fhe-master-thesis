// #include "core/server/context.h"
// #include "core/server/helpers.h"
// #include "core/server/params.h"
// #include "core/client/rgsw.h"
#include "binfhecontext.h"
#include <chrono>

using namespace lbcrypto;

TEST(RGSW, NegS) {
    using namespace lbcrypto;

    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // Set the ciphertext modulus to be 1 << 23
    // Note that normally we do not use this way to obtain the input ciphertext.
    // Instead, we assume that an LWE ciphertext with large ciphertext
    // modulus is already provided (e.g., by extracting from a CKKS ciphertext).
    // However, we do not provide such a step in this example.
    // Therefore, we use a brute force way to create a large LWE ciphertext.
    uint32_t logQ = 23;
    cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);

    uint32_t Q = 1 << logQ;

    int q      = 4096;                                               // q
    int factor = 1 << int(logQ - std::log2(q));                      // Q/q
    uint64_t P = cc.GetMaxPlaintextSpace().ConvertToInt() * factor;  // Obtain the maximum plaintext space

    // Sample Program: Step 2: Key Generation
    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption
    auto ct1 = cc.Encrypt(sk, P / 2 + 1, LARGE_DIM, P, Q);
    std::cout << "Encrypted value: " << P / 2 + 1 << std::endl;

    // Sample Program: Step 4: Evaluation
    // Decompose the large ciphertext into small ciphertexts that fit in q
    auto decomp = cc.EvalDecomp(ct1);

    // Sample Program: Step 5: Decryption
    uint64_t p = cc.GetMaxPlaintextSpace().ConvertToInt();
    std::cout << "Decomposed value: ";
    for (size_t i = 0; i < decomp.size(); i++) {
        ct1 = decomp[i];
        LWEPlaintext result;
        if (i == decomp.size() - 1) {
            // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log GetMaxPlaintextSpace)
            auto logp = GetMSB(P - 1) % GetMSB(p - 1);
            p         = 1 << logp;
        }
        cc.Decrypt(sk, ct1, &result, p);
        std::cout << "(" << result << " * " << cc.GetMaxPlaintextSpace() << "^" << i << ")";
        if (i != decomp.size() - 1) {
            std::cout << " + ";
        }
    }
    std::cout << std::endl;
}
