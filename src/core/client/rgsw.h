#pragma once
#include "openfhe.h"

// #define DEBUG_LOGGING

namespace Client {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

// #if !defined(TEST_INTERNAL_FUNCTIONS)
//  protected: 
// #endif
    /**
     * @brief Encrypt message as RGSW ciphertext
     * 
     * @todo Optimize: EncryptBatch and/or construct b in top row directly
     * @todo Set noise scale for each row
     * @todo Look into setting ell automatically
     * @todo Look into SIMD operations for constructing (top) rows
     * 
     * @param keys Private keys needed
     * @param msg Packed plaintext message to encrypt
     * @param log_B Gadget base power (e.g., 5 gives B = 2^5)
     */
    RGSWCiphertext<DCRTPoly> EncryptRGSW(
        const CryptoContext<DCRTPoly>& cc,
        const PrivateKey<DCRTPoly>& secretKey,
        std::vector<int64_t> msg,
        const uint64_t log_B = 5,
        const size_t ell = 9
    ) {
        RGSWCiphertext<DCRTPoly> G(2 * ell);

        const Plaintext zero   = cc->MakePackedPlaintext({ 0 });
        const Plaintext mPlain = cc->MakePackedPlaintext(msg);
        if (!mPlain->Encode())
            throw std::runtime_error("Failed to encode plaintext");

        // Scale m by B^i at the R_Q polynomial level (per-tower integer mul),
        // NOT at the R_t plaintext level. Going through MakePackedPlaintext would
        // reduce each slot mod t, introducing a carry polynomial K_i with
        // |K_i| ~ B^i. The external product then produces t·Σv[i]·K_i, which
        // overflows Q and contaminates the result mod t.
        DCRTPoly mScaled = mPlain->GetElement<DCRTPoly>();
        mScaled.SetFormat(Format::EVALUATION);

        const NativeInteger B(1ULL << log_B);

        for (size_t i = 0; i < ell; i++) {
            // Bottom row i+ell: message is m·B^i (injected into c0).
            // c0 + c1·s = t·e + m·B^i
            {
                auto bot     = cc->Encrypt(secretKey, zero);
                auto& elems  = bot->GetElements();
                DCRTPoly add = mScaled;
                add.SetFormat(elems[0].GetFormat());
                elems[0] += add;
                G[i + ell] = bot;
            }

            // Top row i: message is m·B^i·s (injected into c1).
            // c0 + c1·s = t·e + m·B^i·s
            {
                auto top     = cc->Encrypt(secretKey, zero);
                auto& elems  = top->GetElements();
                DCRTPoly add = mScaled;
                add.SetFormat(elems[1].GetFormat());
                elems[1] += add;
                G[i] = top;
            }

            mScaled *= B;  // mScaled ← m · B^{i+1} (per RNS tower)
        }

        return G;
    }
}

namespace Server {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    // Helper: multiply each component of an RLWE ciphertext by a scalar polynomial
    static Ciphertext<DCRTPoly> ScalarMultCiphertext(
        const Ciphertext<DCRTPoly>& ct,
        const DCRTPoly& scalar
    ) {
        auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ct);
        auto& elems = result->GetElements();
        elems[0] *= scalar;
        elems[1] *= scalar;
        return result;
    }

    /**
     * @brief Homomorphically evaluate the external product
     * 
     * @param cc 
     * @param x 
     * @param Y 
     * @param log_B 
     * @param ell 
     * @return Ciphertext<DCRTPoly> 
     */
    Ciphertext<DCRTPoly> EvalExternalProduct(
        const CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        const RGSWCiphertext<DCRTPoly>& Y,
        const uint64_t log_B,
        const size_t ell
    ) {
        // Decompose both ciphertext components in base B.
        // BaseDecompose operates per-limb in RNS — this is correct because
        // ell is chosen to cover the full product modulus (ell = ceil(log_B(q))).
        DCRTPoly b = x->GetElements()[0];
        DCRTPoly a = x->GetElements()[1];
        b.SetFormat(Format::COEFFICIENT);
        a.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> v = b.BaseDecompose(log_B, true); // digits of b
        std::vector<DCRTPoly> u = a.BaseDecompose(log_B, true); // digits of a

        // auto zero = DCRTPoly(b.GetParams(), Format::EVALUATION, true);
        // v.resize(ell, zero);
        // u.resize(ell, zero);

        if (u.size() != ell || v.size() != ell) {
            std::cout << "Size mismatch: " << u.size() << " / " << ell << ", " << v.size() << " / " << ell << std::endl;
            throw std::runtime_error("BaseDecompose depth mismatch — check ell vs log_B vs q");
        }

        // Accumulate: result = sum_i u[i]*Y[i] + sum_i v[i]*Y[ell+i]
        auto result = ScalarMultCiphertext(Y[0], u[0]);
        for (size_t i = 1; i < ell; i++) {
            // Plaintext step;
            // cc->Decrypt(keys.secretKey, result, &step);
            // std::cout << step << std::endl;
            result = cc->EvalAdd(result, ScalarMultCiphertext(Y[i],       u[i]));
        }
        for (size_t i = 0; i < ell; i++) {
            // Plaintext step;
            // cc->Decrypt(keys.secretKey, result, &step);
            // std::cout << step << std::endl;
            result = cc->EvalAdd(result, ScalarMultCiphertext(Y[i + ell], v[i]));
        }

        return result;
    }
}