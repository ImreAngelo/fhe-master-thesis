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

    //-----------------//
    // implementations //
    //-----------------//

    // RGSW addition
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalAddRGSW(
        const Context::ExtendedCryptoContext<T>& cc,
        const RGSWCiphertext<T>& A,
        const RGSWCiphertext<T>& B
    ) {
        RGSWCiphertext<T> result(A.size());
        for (size_t i = 0; i < A.size(); i++) {
            result[i] = cc->EvalAdd(A[i], B[i]);
        }
        return result;
    }

    // RGSW subtraction
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalSubRGSW(
        const Context::ExtendedCryptoContext<T>& cc,
        const RGSWCiphertext<T>& A,
        const RGSWCiphertext<T>& B
    ) {
        RGSWCiphertext<T> result(A.size());
        for (size_t i = 0; i < A.size(); i++) {
            result[i] = cc->EvalSub(A[i], B[i]);
        }
        return result;
    }

    // RGSW x Plaintext multiplication
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalMultPlain(
        const Context::ExtendedCryptoContext<T>& cc,
        const Plaintext& p,
        const RGSWCiphertext<T>& A
    ) {
        RGSWCiphertext<T> result(A.size());
        for (size_t i = 0; i < A.size(); i++) {
            result[i] = cc->EvalMult(p, A[i]);
        }
        return result;
    }

    // Decrypt RGSW
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const Context::ExtendedCryptoContext<T>& cc,
        const PrivateKey<T>& secretKey,
        const RGSWCiphertext<T>& rgsw,
        const size_t len = 1
    ) {
        Plaintext res;
        cc->Decrypt(secretKey, rgsw[rgsw.size()/2], &res);
        res->SetLength(len);
        return res->GetCoefPackedValue();
    }

    // Decrypt RLWE
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const Context::ExtendedCryptoContext<T>& cc,
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
        template <typename Poly = DCRTPoly, typename T, size_t K, uint64_t N>
        void PrintMatrix(const std::string& label, const Context::ExtendedCryptoContext<Poly>& cc, const std::array<std::array<T, K>, N>& mat, const PrivateKey<DCRTPoly>& secretKey) {
            DEBUG_PRINT_SAMELINE(label << ": ");
        #if defined(DEBUG_LOGGING)
            for (uint64_t i = 0; i < N; i++) {
                DEBUG_PRINT_SAMELINE("\t[ ");
                for (size_t k = 0; k < K; k++) {
                    auto cell = server::Decrypt(cc, secretKey, mat[i][k]);
                    DEBUG_PRINT_SAMELINE(cell[0] << (k == K - 1 ? " ]\n" : ", "));
                }
            }
        #endif
        }

        template <typename Poly = DCRTPoly, typename T, size_t K>
        void PrintRow(const std::string& label, const Context::ExtendedCryptoContext<Poly>& cc, const std::array<T, K>& row, const PrivateKey<DCRTPoly>& secretKey) {
            DEBUG_PRINT_SAMELINE(label << ":\t[ ");
        #if defined(DEBUG_LOGGING)
            for (size_t k = 0; k < K; k++) {
                auto cell = server::Decrypt(cc, secretKey, row[k]);
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
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const Plaintext& Vr,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& L_mat,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& I_mat,
        const std::array<std::array<RGSWCiphertext<T>, (uint64_t(1) << L)>, D>& z,
        const PrivateKey<T>& secretKey, // for debugging
        const uint32_t iteration = 1
    ) {
        constexpr uint64_t N = (uint64_t(1) << L);

        const auto one  = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        const auto zero = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

        // Phase 2: parallel availability — depth 1, all N products per (d,k) are independent.
        // avail[d][k] = Σ_i (z[d][i] ⊠ I_mat[i][k])  collapses to I_mat[sel_d][k] obliviously.
        std::array<std::array<RGSWCiphertext<T>, K>, D> avail;
        {
            DEBUG_TIMER("Phase 2: availability");
            for (uint32_t d = 0; d < D; d++) {
                for (uint32_t k = 0; k < K; k++) {
                    avail[d][k] = zero;
                    for (uint64_t i = 0; i < N; i++) {
                        auto term = cc->EvalInternalProduct(z[d][i], I_mat[i][k]);
                        avail[d][k] = EvalAddRGSW(cc, avail[d][k], term);
                    }
                    DEBUG_PRINT("avail[" << d << "][" << k << "]: " << Decrypt(cc, secretKey, avail[d][k]));
                }
            }
        }

        // Phase 3: fixed-depth D×K-way priority selection — depth grows by 1 per (d,k) step,
        // bounded at D×K regardless of N.
        std::array<std::array<RGSWCiphertext<T>, K>, D> w;
        auto hasWritten = zero;
        {
            DEBUG_TIMER("Phase 3: selection");
            for (uint32_t d = 0; d < D; d++) {
                for (uint32_t k = 0; k < K; k++) {
                    auto not_written = EvalSubRGSW(cc, one, hasWritten);
                    w[d][k] = cc->EvalInternalProduct(avail[d][k], not_written);
                    hasWritten = EvalAddRGSW(cc, hasWritten, w[d][k]);
                    DEBUG_PRINT("w[" << d << "][" << k << "]: " << Decrypt(cc, secretKey, w[d][k]));
                }
            }
            DEBUG_PRINT("hasWritten: " << Decrypt(cc, secretKey, hasWritten));
        }

        // Phase 4: parallel write-back — depth 1 more (= D×K+1 total), all N products independent.
        {
            DEBUG_TIMER("Phase 4: write-back");
            for (uint32_t d = 0; d < D; d++) {
                for (uint32_t k = 0; k < K; k++) {
                    for (uint64_t i = 0; i < N; i++) {
                        auto selected = cc->EvalInternalProduct(w[d][k], z[d][i]);
                        auto val = EvalMultPlain(cc, Vr, selected);
                        L_mat[i][k] = EvalAddRGSW(cc, L_mat[i][k], val);
                        I_mat[i][k] = EvalSubRGSW(cc, I_mat[i][k], selected);
                    }
                }
            }
            debug::PrintMatrix("L", cc, L_mat, secretKey); DEBUG_PRINT("");
            debug::PrintMatrix("I", cc, I_mat, secretKey); DEBUG_PRINT("");
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
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const size_t index
    ) {
        std::array<std::array<server::RGSWCiphertext<T>, (uint64_t(1) << L)>, D> z;
        auto one  = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        auto zero = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

        for (uint32_t d = 0; d < D; d++)
            for (uint64_t slot = 0; slot < (uint64_t(1) << L); slot++)
                z[d][slot] = (slot == index) ? one : zero;

        return z;
    }
}
