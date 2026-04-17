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
            // TODO: Use SIMD for scalar * vector (mod t if possible)
            std::vector<int64_t> row = msg;
            for(size_t j = 0; j < slots; j++) {
                row[j] *= gi;
                row[j] %= t;
            }

            Plaintext mBi = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(secretKey, mBi);
            
            // Top L rows: -s * msg * B^i
            // enc(-s * msg * B^i) = Enc(0) - Enc(msg * B^i)
            // TODO: Confirm identity in main doc, it should follow directly from Z - \mu G with Z = RLWE(0)
            auto top = cc->Encrypt(secretKey, zero); // WARN: create *fresh* ciphertext of 0 each iteration 
            
            if(!mBi->Encode()) // ensure DCRTPoly form is populated
                throw std::runtime_error("mBi is not DCRTPoly");

            auto mBiPoly = mBi->GetElement<DCRTPoly>();

            auto& elems = top->GetElements();
            mBiPoly.SetFormat(elems[1].GetFormat());  // match NTT/coeff form of c1
            elems[1] -= mBiPoly;

            G[i] = top;
        }
    
    #if defined(DEBUG_LOGGING)
        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(secretKey, row, &decrytedRow);
            decrytedRow->SetLength(slots);
            std::cout << decrytedRow << std::endl;

            // TODO: Assert bottom rows are correct (in test)
        }
    #endif

        return G;
    }
}

namespace Server {
    using namespace lbcrypto;
    
    template <typename T>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    /**
     * @brief Evaluate external product homomorphically
     */
    Ciphertext<DCRTPoly> EvalExternalProduct(
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

        // ── Step 2: out = Σ u_i · Y[i+ℓ]  -  Σ v_i · Y[i] ────────────────────
        //   Y[i]     (0 ≤ i < ℓ): Enc(-μ·B^i·s)   ["top"    rows, our labeling]
        //   Y[i+ℓ]   (0 ≤ i < ℓ): Enc( μ·B^i )    ["bottom" rows, our labeling]
        //
        // Decryption check:
        //   out_0 + out_1·s
        //     = Σ u_i·(μ·B^i)  -  Σ v_i·(-μ·B^i·s)       (+ t·noise)
        //     = μ·(Σ u_i·B^i) + μ·s·(Σ v_i·B^i)
        //     = μ·(x_0 + x_1·s) = μ·m_x                  ✓
        auto out = scalarMult(Y[ell], u[0]);
        for (size_t i = 1; i < ell; i++) {
            out = cc->EvalAdd(out, scalarMult(Y[i + ell], u[i]));
        }
        for (size_t i = 0; i < ell; i++) {
            out = cc->EvalSub(out, scalarMult(Y[i], v[i]));
        }

        return out;
    }
}