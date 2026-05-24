#pragma once

#include "openfhe.h"
#include "core/context.h"
#include "utils/timer.h"
#include "utils/logging.h"

#if defined(DEBUG_LOGGING) || defined(DEBUG)
    #define DEBUG_PRINT_SAMELINE(x) std::cout << x;
#else
    #define DEBUG_PRINT_SAMELINE(x)
#endif


namespace server {
    using namespace lbcrypto;

    template <typename T = DCRTPoly>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T = DCRTPoly>
    using RGSWCiphertext = std::vector<RLWECiphertext<T>>;

    //---------//
    // Helpers //
    //---------//

    // Element-wise add of two RGSW ciphertexts
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalAddRGSW(
        const CryptoContext<T>& cc,
        const RGSWCiphertext<T>& lhs,
        const RGSWCiphertext<T>& rhs
    ) {
        RGSWCiphertext<T> out(lhs.size());
        for (size_t i = 0; i < lhs.size(); i++) {
            out[i] = cc->EvalAdd(lhs[i], rhs[i]);
        }
        return out;
    }

    // Element-wise subtract of two RGSW ciphertexts
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalSubRGSW(
        const CryptoContext<T>& cc,
        const RGSWCiphertext<T>& lhs,
        const RGSWCiphertext<T>& rhs
    ) {
        RGSWCiphertext<T> out(lhs.size());
        for (size_t i = 0; i < lhs.size(); i++) {
            out[i] = cc->EvalSub(lhs[i], rhs[i]);
        }
        return out;
    }

    // Multiply each RLWE row of an RGSW ciphertext by a plaintext.
    // Done at the DCRTPoly level to avoid the modulus-switch that BGV's
    // EvalMult(ct, pt) can trigger, which would leave the result with fewer
    // towers than other RGSW ciphertexts and break later external products.
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalMultRGSW(
        const CryptoContext<T>& /*cc*/,
        const RGSWCiphertext<T>& rgsw,
        const Plaintext& pt
    ) {
        T ptPoly = pt->GetElement<T>();
        ptPoly.SetFormat(Format::EVALUATION);

        RGSWCiphertext<T> out(rgsw.size());
        for (size_t i = 0; i < rgsw.size(); i++) {
            auto ct = rgsw[i]->Clone();
            auto elements = ct->GetElements();
            for (auto& e : elements) {
                e.SetFormat(Format::EVALUATION);
                e *= ptPoly;
            }
            ct->SetElements(std::move(elements));
            out[i] = ct;
        }
        return out;
    }

    // Decrypt RGSW
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const CryptoContext<T>& cc,
        const Core::HPSContext& bv,
        const PrivateKey<T>& secretKey,
        const RGSWCiphertext<T>& rgsw,
        const size_t len = 1
    ) {
        const auto one = cc->Encrypt(secretKey, cc->MakeCoefPackedPlaintext({ 1 }));
        const auto rlwe = bv.EvalExternalProduct(one, rgsw);

        Plaintext res;
        cc->Decrypt(secretKey, rlwe, &res);
        res->SetLength(len);
        return res->GetCoefPackedValue();
    }

    // Decrypt RLWE
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const CryptoContext<T>& cc,
        const Core::HPSContext& /*bv*/,
        const PrivateKey<T>& secretKey,
        const RLWECiphertext<T>& rlwe,
        const size_t len = 1
    ) {
        Plaintext res;
        cc->Decrypt(secretKey, rlwe, &res);
        res->SetLength(len);
        return res->GetCoefPackedValue();
    }

    // --------- //
    // Debugging //
    // --------- //

    namespace debug {
        template <size_t K, uint64_t N>
        void PrintMatrix(const std::string& label, const CryptoContext<DCRTPoly>& cc, const Core::HPSContext& bv, const std::array<std::array<server::RGSWCiphertext<DCRTPoly>, K>, N>& mat, const PrivateKey<DCRTPoly>& secretKey) {
            DEBUG_PRINT_SAMELINE(label << ": ");
        #if defined(DEBUG_LOGGING)
            for (uint64_t i = 0; i < N; i++) {
                DEBUG_PRINT_SAMELINE("\t[ ");
                for (size_t k = 0; k < K; k++) {
                    auto cell = server::Decrypt(cc, bv, secretKey, mat[i][k]);
                    DEBUG_PRINT_SAMELINE(cell[0] << (k == K - 1 ? " ]\n" : ", "));
                }
            }
        #endif
        }

        template <typename Poly = DCRTPoly, typename T, size_t K>
        void PrintRow(const std::string& label, const CryptoContext<Poly>& cc, const Core::HPSContext& bv, const std::array<T, K>& row, const PrivateKey<DCRTPoly>& secretKey) {
            DEBUG_PRINT_SAMELINE(label << ":\t[ ");
        #if defined(DEBUG_LOGGING)
            for (size_t k = 0; k < K; k++) {
                auto cell = server::Decrypt(cc, bv, secretKey, row[k]);
                DEBUG_PRINT_SAMELINE(cell[0] << (k == K - 1 ? " ]\n" : ", "));
            }
        #endif
        }
    }
    
    /**
     * @brief Loop 2 of sPAR Algorithm 2
     * 
     * @tparam T DCRTPoly
     * @tparam K Bins 
     * @tparam D Number of choices (default = A1, A2, A3)
     * @tparam L Number of bits (N = 2^L users)
     * 
     * @param cc CryptoContext with RGSW support
     * @param publicKey Public key for encryption
     * @param Vr Encrypted (non-fhe) value
     * @param L_mat Left matrix of RGSW ciphertexts
     * @param I_mat Right matrix of RGSW ciphertexts
     * 
     * @returns encrypted boolean indicating whether the operation was successful
     */
    template <typename T = DCRTPoly, uint32_t K = 3, uint32_t D = 3, uint32_t L = 1>
    inline RGSWCiphertext<T> Write(
        const CryptoContext<T>& cc,
        const Core::HPSContext& bv,
        const PublicKey<T>& publicKey,
        const Plaintext& Vr,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& L_mat,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& I_mat,
        const std::array<std::array<RGSWCiphertext<T>, (uint64_t(1) << L)>, D>& z,
        const PrivateKey<T>& secretKey, // for debugging
        const uint32_t iteration = 1
    ) {
        const auto one  = bv.EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 1 }), true);
        auto hasWritten = bv.EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 0 }), true);

        {
            DEBUG_TIMER("Server Write");

            // FASTER: First user always writes to their preferred slot/bin
            for(uint32_t d = 0; d < std::min(D, iteration); d++) {
                DEBUG_PRINT("candidate: " << d << " < " << std::min(D, iteration));
                for (uint32_t k = 0; k < std::min(K, iteration); k++) {
                    DEBUG_PRINT("bin: " << k << " < " << std::min(K, iteration));
                    for (uint64_t i = 0; i < (uint64_t(1) << L); i++) {
                        DEBUG_PRINT("slot: " << i);
                        DEBUG_TIMER("iteration");

                        auto zI  = bv.EvalInternalProduct(z[d][i], I_mat[i][k]);
                        DEBUG_PRINT("Available and asking? " << Decrypt(cc, bv, secretKey, zI));

                        auto sub = EvalSubRGSW(cc, one, hasWritten);
                        DEBUG_PRINT("Can write? " << Decrypt(cc, bv, secretKey, sub));

                        auto h   = bv.EvalInternalProduct(zI, sub);
                        DEBUG_PRINT("Will write? " << Decrypt(cc, bv, secretKey, h));

                        auto val = EvalMultRGSW(cc, h, Vr);
                        DEBUG_PRINT("Value to write: " << Decrypt(cc, bv, secretKey, val));

                        debug::PrintRow("L_mat[" + std::to_string(i) + "] before", cc, bv, L_mat[i], secretKey);
                        L_mat[i][k] = EvalAddRGSW(cc, L_mat[i][k], val);
                        debug::PrintRow("L_mat[" + std::to_string(i) + "] after", cc, bv, L_mat[i], secretKey);

                        I_mat[i][k] = EvalSubRGSW(cc, I_mat[i][k], h);
                        DEBUG_PRINT("I_mat[" << i << "][" << k << "]: " << Decrypt(cc, bv, secretKey, I_mat[i][k]));

                        DEBUG_PRINT("hasWritten before add: " << Decrypt(cc, bv, secretKey, hasWritten));
                        hasWritten = EvalAddRGSW(cc, hasWritten, h);
                        DEBUG_PRINT("hasWritten: " << Decrypt(cc, bv, secretKey, hasWritten));

                        debug::PrintMatrix("L", cc, bv, L_mat, secretKey); DEBUG_PRINT("");
                        debug::PrintMatrix("I", cc, bv, I_mat, secretKey); DEBUG_PRINT("");
                    }
                }
            }
        }

        DEBUG_PRINT("");
        return hasWritten;
    };
} // namespace server

namespace client {
    using namespace lbcrypto;

    /**
     * @brief Loop 1 of algorithm 2, performed on client-side
     * 
     * Returns a vector of RGSW encryptions where the n-th entry is 1
     * 
     * @tparam T 
     * @tparam D 
     * @tparam L 
     */
    template <typename T = DCRTPoly, uint32_t D = 3, uint32_t L = 1>
    inline std::array<std::array<server::RGSWCiphertext<T>, (uint64_t(1) << L)>, D> PlaceAtN(
        const CryptoContext<T>& cc,
        const Core::HPSContext& bv,
        const PublicKey<T>& publicKey,
        const size_t index
    ) {
        std::array<std::array<server::RGSWCiphertext<T>, (uint64_t(1) << L)>, D> z;
        
        for (uint32_t d = 0; d < D; d++)
            for (uint64_t slot = 0; slot < (uint64_t(1) << L); slot++)
                z[d][slot] = (slot == index) 
                    ? bv.EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 1 }))
                    : bv.EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

        return z;
    }
}
