#pragma once

#include "openfhe.h"
#include "core/context.h"
#include "utils/timer.h"


namespace server {
    using namespace lbcrypto;

    template <typename T = DCRTPoly>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T = DCRTPoly>
    using RGSWCiphertext = std::vector<RLWECiphertext<T>>;

    // -------------------------------- //
    // Easily swappable implementations //
    // -------------------------------- //

    // Encrypt RGSW
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> Encrypt(
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const Plaintext& plaintext
    ) {
        return cc->Encrypt_Textbook(publicKey, plaintext, 10, 21);
    }

    // EvalExternalProduct
    template <typename T = DCRTPoly>
    inline RLWECiphertext<T> EvalExternalProduct(
        const Context::ExtendedCryptoContext<T>& cc,
        const RLWECiphertext<T>& rlwe,
        const RGSWCiphertext<T>& rgsw
    ) {
        return cc->EvalExternalProduct_Textbook(rlwe, rgsw, 10);
    }

    // EvalInternalProduct
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalInternalProduct(
        const Context::ExtendedCryptoContext<T>& cc,
        const RGSWCiphertext<T>& left,
        const RGSWCiphertext<T>& right
    ) {
        return cc->EvalInternalProduct_Textbook(left, right, 10);
    }

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
    
    // -------------------------------- //
    // Easily swappable implementations //
    // -------------------------------- //
    
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
    template <typename T = DCRTPoly, size_t K = 3, uint32_t D = 3, uint32_t L = 1>
    inline RGSWCiphertext<T> Write(
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const Plaintext& Vr,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& L_mat,
        std::array<std::array<RGSWCiphertext<T>, K>, (uint64_t(1) << L)>& I_mat,
        const std::array<std::array<RGSWCiphertext<T>, D>, (uint64_t(1) << L)>& z
    ) {
        const auto one  = Encrypt(cc, publicKey, cc->MakePackedPlaintext({ 1 }));
        auto hasWritten = Encrypt(cc, publicKey, cc->MakePackedPlaintext({ 0 }));

        {
            DEBUG_TIMER("server:write");
    
            for(uint32_t d = 0; d < D; d++) {
                for (uint32_t k = 0; k < K; k++) {
                    for (uint64_t i = 0; i < (uint64_t(1) << L); i++) {
                        DEBUG_TIMER("server:write iteration");
                        auto zI  = server::EvalInternalProduct(cc, z[i][d], I_mat[i][k]);
                        auto sub = server::EvalSubRGSW(cc, one, hasWritten);
                        auto h   = server::EvalInternalProduct(cc, zI, sub);
    
                        L_mat[i][k] = server::EvalAddRGSW(cc, L_mat[i][k], server::EvalMultPlain(cc, Vr, h));
                        I_mat[i][k] = server::EvalSubRGSW(cc, I_mat[i][k], h);

                        hasWritten = server::EvalAddRGSW(cc, hasWritten, h);
                    }
                }
            }
        }

        return hasWritten;
    };
}

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
    inline std::array<std::array<server::RGSWCiphertext<T>, D>, (uint64_t(1) << L)> PlaceAtN(
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const std::array<size_t, D> index
    ) {
        std::array<std::array<server::RGSWCiphertext<T>, D>, (uint64_t(1) << L)> z;

        for (uint64_t i = 0; i < (uint64_t(1) << L); i++) {
            for (uint32_t d = 0; d < D; d++) {
                z[i][d] = (i == index[d]) 
                    ? server::Encrypt(cc, publicKey, cc->MakePackedPlaintext({ 1 }))
                    : server::Encrypt(cc, publicKey, cc->MakePackedPlaintext({ 0 }))
                ;
            }
        }

        return z;
    }
}
