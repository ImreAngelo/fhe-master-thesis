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
        const CryptoContext<DCRTPoly>& cc,  // TODO: Make ->encryptRGSW member of ClientImpl
        const PrivateKey<DCRTPoly>& secretKey,
        std::vector<int64_t> msg,
        const uint64_t log_B = 5,           // TODO: Make crypto parameter
        const size_t ell = 9                // TODO: Make crypto parameter
    ) {
        const auto t = cc->GetCryptoParameters()->GetPlaintextModulus();
        const auto B = (1ULL << log_B); 
        const auto slots = msg.size();
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        
        const Plaintext zero = cc->MakePackedPlaintext({ 0 });
        int64_t gi = 1; 

        for (size_t i = 0; i < ell; i++, gi = (gi * B) % t) {
            
            #if defined(DEBUG_LOGGING)
            std::cout << "B^" << i << " = " << gi << " mod " << t << std::endl;
            #endif

            // Bottom L rows: msg * B^i
            std::vector<int64_t> row = msg;
            for(size_t j = 0; j < slots; j++) {
                row[j] *= gi;
                row[j] %= t;
            }

            Plaintext mBi = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(secretKey, mBi);
            
            // Top L rows: a + msg * B^i
            // WARN: create *fresh* ciphertext of 0 each iteration 
            auto top = cc->Encrypt(secretKey, zero); 
            
            if(!mBi->Encode()) // ensure correct form
                throw std::runtime_error("mBi is not DCRTPoly");

            auto mBiPoly = mBi->GetElement<DCRTPoly>();

            auto& s = top->GetElements();
            mBiPoly.SetFormat(s[1].GetFormat());  // match NTT/coeff form of c1
            s[1] += mBiPoly;

            G[i] = top;
        }

        return G;
    }
}

namespace Server {
    using namespace lbcrypto;
    
    template <typename T>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    // Helper: multiply each component of an RLWE ciphertext by a scalar polynomial
    static Ciphertext<DCRTPoly> ScalarMultCiphertext(
        const Ciphertext<DCRTPoly>& ct,
        const DCRTPoly& scalar
    ) {
        auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ct);
        auto& elems = result->GetElements();

        // Digit polys from BaseDecompose come out in COEFFICIENT format;
        // ciphertext elements are in EVALUATION (NTT). Must match before multiply.
        // scalar.SetFormat(EVALUATION);

        elems[0] *= scalar;
        elems[1] *= scalar;
        return result;
    }

    Ciphertext<DCRTPoly> EvalExternalProduct(
        const CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        const RGSWCiphertext<DCRTPoly>& Y,
        const uint64_t log_B,
        const size_t ell
        // const KeyPair<DCRTPoly>& keys
    ) {
        // const auto& elems = x->GetElements(); // {c0=b, c1=a}

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

    /**
     * @brief Evaluate external product homomorphically
     */
    Ciphertext<DCRTPoly> EvalCoeffExternalProduct(
        const CryptoContext<DCRTPoly>& cc,  // TODO: Make ->encryptRGSW member of ClientImpl
        // const PublicKey<DCRTPoly>& publicKey,
        RLWECiphertext<DCRTPoly> x,
        RGSWCiphertext<DCRTPoly> Y,
        const uint64_t log_B = 5,           // TODO: Make crypto parameter
        const size_t ell = 9                // TODO: Make crypto parameter
    ) {
        // Scalar-multiply a ciphertext by a polynomial
        auto scalarMult = [](const Ciphertext<DCRTPoly>& ct, const DCRTPoly& poly) {
            auto result = ct->Clone();
            auto& elems = result->GetElements();
            DCRTPoly p = poly;
            p.SetFormat(elems[0].GetFormat());
            elems[0] *= p;
            elems[1] *= p;
            return result;
        };

        // Base-B decomposition of x_0 and x_1
        // Produces digit polynomials {u_i}, {v_i} with small coefficients
        // such that  Σ u_i·B^i ≡ x_0 (mod q)  and  Σ v_i·B^i ≡ x_1 (mod q).
        DCRTPoly x0 = x->GetElements()[0];
        DCRTPoly x1 = x->GetElements()[1];
        x0.SetFormat(Format::COEFFICIENT);
        x1.SetFormat(Format::COEFFICIENT);

        auto u = x0.BaseDecompose(log_B, /*evalModeAnswer=*/true);
        auto v = x1.BaseDecompose(log_B, /*evalModeAnswer=*/true);

        // BaseDecompose returns ⌈log_B q⌉ digits. If ell is smaller, high-order
        // digits are dropped here — which IS an error (see caveat below).
        auto zero = DCRTPoly(x0.GetParams(), Format::EVALUATION, /*zero=*/true);
        u.resize(ell, zero);
        v.resize(ell, zero);

        auto out = scalarMult(Y[ell], u[0]);
        for (size_t i = 1; i < ell; i++) {
            out = cc->EvalAdd(out, scalarMult(Y[i + ell], u[i]));
        }
        for (size_t i = 0; i < ell; i++) {
            out = cc->EvalAdd(out, scalarMult(Y[i], v[i]));
        }

        return out;
    }

    // Accumulate in-place at the polynomial level, bypassing BGV level tracking
    static void AccumulateInPlace(Ciphertext<DCRTPoly>& acc, const Ciphertext<DCRTPoly>& ct) {
        auto& ae = acc->GetElements();
        const auto& ce = ct->GetElements();
        ae[0] += ce[0];
        ae[1] += ce[1];
    }

    Ciphertext<DCRTPoly> EvalAccExternalProduct(
        const CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        const RGSWCiphertext<DCRTPoly>& Y,
        const uint64_t log_B,
        const size_t ell
    ) {
        DCRTPoly b = x->GetElements()[0];
        DCRTPoly a = x->GetElements()[1];
        b.SetFormat(Format::COEFFICIENT);
        a.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> u = a.BaseDecompose(log_B, true);
        std::vector<DCRTPoly> v = b.BaseDecompose(log_B, true);

        if (u.size() != ell || v.size() != ell)
            throw std::runtime_error("BaseDecompose depth mismatch");

        Ciphertext<DCRTPoly> result = ScalarMultCiphertext(Y[0], u[0]);
        for (size_t i = 1; i < ell; i++)
            AccumulateInPlace(result, ScalarMultCiphertext(Y[i],       u[i]));
        for (size_t i = 0; i < ell; i++)
            AccumulateInPlace(result, ScalarMultCiphertext(Y[i + ell], v[i]));

        return result;
    }
}