#pragma once

#include "openfhe.h"
#include "core/include/context.h"
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

    // Decrypt RGSW
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const Context::ExtendedCryptoContext<T>& cc,
        const PrivateKey<T>& secretKey,
        const RGSWCiphertext<T>& rgsw,
        const size_t len = 1
    ) {
        const auto one = cc->Encrypt(secretKey, cc->MakeCoefPackedPlaintext({ 1 }));
        const auto rlwe = cc->EvalExternalProduct(one, rgsw);

        Plaintext res;
        cc->Decrypt(secretKey, rlwe, &res);
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
        template <size_t K, uint64_t N>
        void PrintMatrix(const std::string& label, const Context::ExtendedCryptoContext<DCRTPoly>& cc, const std::array<std::array<server::RGSWCiphertext<DCRTPoly>, K>, N>& mat, const PrivateKey<DCRTPoly>& secretKey) {
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
        const auto one  = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        auto hasWritten = cc->EncryptRGSW(publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

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
                        
                        auto zI  = cc->EvalInternalProduct(z[d][i], I_mat[i][k]);
                        DEBUG_PRINT("Available and asking? " << Decrypt(cc, secretKey, zI));

                        auto sub = cc->EvalSubRGSW(one, hasWritten);
                        DEBUG_PRINT("Can write? " << Decrypt(cc, secretKey, sub));

                        auto h   = cc->EvalInternalProduct(zI, sub);
                        DEBUG_PRINT("Will write? " << Decrypt(cc, secretKey, h));
    
                        auto val = cc->EvalMultRGSW(h, Vr);
                        DEBUG_PRINT("Value to write: " << Decrypt(cc, secretKey, val));

                        debug::PrintRow("L_mat[" + std::to_string(i) + "] before", cc, L_mat[i], secretKey);
                        L_mat[i][k] = cc->EvalAddRGSW(L_mat[i][k], val);
                        debug::PrintRow("L_mat[" + std::to_string(i) + "] after", cc, L_mat[i], secretKey);

                        I_mat[i][k] = cc->EvalSubRGSW(I_mat[i][k], h);
                        DEBUG_PRINT("I_mat[" << i << "][" << k << "]: " << Decrypt(cc, secretKey, I_mat[i][k]));

                        DEBUG_PRINT("hasWritten before add: " << Decrypt(cc, secretKey, hasWritten));
                        hasWritten = cc->EvalAddRGSW(hasWritten, h);
                        DEBUG_PRINT("hasWritten: " << Decrypt(cc, secretKey, hasWritten));

                        debug::PrintMatrix("L", cc, L_mat, secretKey); DEBUG_PRINT("");
                        debug::PrintMatrix("I", cc, I_mat, secretKey); DEBUG_PRINT("");
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
