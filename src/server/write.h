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

    // TODO: Pass as args
    constexpr uint32_t B_LOG = 15;

    // ------------------------- //
    // Swappable implementations //
    // ------------------------- //

    // Encrypt RGSW
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> Encrypt(
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const Plaintext& plaintext
    ) {
        const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
        const size_t ell = log_q / B_LOG + 1;
        return cc->EncryptRGSW(publicKey, plaintext, B_LOG, ell);
    }

    // EvalExternalProduct
    template <typename T = DCRTPoly>
    inline RLWECiphertext<T> EvalExternalProduct(
        const Context::ExtendedCryptoContext<T>& cc,
        const RLWECiphertext<T>& rlwe,
        const RGSWCiphertext<T>& rgsw
    ) {
        return cc->EvalExternalProduct(rlwe, rgsw, B_LOG);
    }

    // EvalInternalProduct
    template <typename T = DCRTPoly>
    inline RGSWCiphertext<T> EvalInternalProduct(
        const Context::ExtendedCryptoContext<T>& cc,
        const RGSWCiphertext<T>& left,
        const RGSWCiphertext<T>& right
    ) {
        return cc->EvalInternalProduct(left, right, B_LOG);
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

    // Decrypt RGSW
    template <typename T = DCRTPoly>
    inline std::vector<int64_t> Decrypt(
        const Context::ExtendedCryptoContext<T>& cc,
        const PrivateKey<T>& secretKey,
        const RGSWCiphertext<T>& rgsw,
        const size_t len = 1
    ) {
        Plaintext res;
        auto rlwe_one = cc->Encrypt(secretKey, cc->MakeCoefPackedPlaintext({ 1 }));
        cc->Decrypt(secretKey, server::EvalExternalProduct(cc, rlwe_one, rgsw), &res);
        res->SetLength(len);
        return res->GetCoefPackedValue();
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
        const auto one  = Encrypt(cc, publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        auto hasWritten = Encrypt(cc, publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

        {
            DEBUG_TIMER("Server Write");
    
            // FASTER: First user always writes to their preferred slot/bin
            for(uint32_t d = 0; d < std::min(D, iteration); d++) {
                DEBUG_PRINT("candidate: " << d);
                for (uint32_t k = 0; k < std::min(K, iteration); k++) {
                    DEBUG_PRINT("bin: " << k);
                    for (uint64_t i = 0; i < (uint64_t(1) << L); i++) {
                        DEBUG_PRINT("slot: " << i);
                        DEBUG_TIMER("iteration");
                        
                        auto zI  = EvalInternalProduct(cc, z[d][i], I_mat[i][k]);
                        DEBUG_PRINT("Available and asking? " << Decrypt(cc, secretKey, zI));

                        auto sub = EvalSubRGSW(cc, one, hasWritten);
                        DEBUG_PRINT("Can write? " << Decrypt(cc, secretKey, sub));

                        auto h   = EvalInternalProduct(cc, zI, sub);
                        DEBUG_PRINT("Will write? " << Decrypt(cc, secretKey, h));
    
                        auto val = server::EvalMultPlain(cc, Vr, h);
                        DEBUG_PRINT("Value to write: " << Decrypt(cc, secretKey, val));

                        DEBUG_PRINT("L_mat[" << i << "][" << k << "] before writing: " << Decrypt(cc, secretKey, L_mat[i][k]));
                        L_mat[i][k] = EvalAddRGSW(cc, L_mat[i][k], val);
                        DEBUG_PRINT("L_mat[" << i << "][" << k << "]: " << Decrypt(cc, secretKey, L_mat[i][k]));

                        I_mat[i][k] = EvalSubRGSW(cc, I_mat[i][k], h);
                        DEBUG_PRINT("I_mat[" << i << "][" << k << "]: " << Decrypt(cc, secretKey, I_mat[i][k]));

                        hasWritten = EvalAddRGSW(cc, hasWritten, h);
                        DEBUG_PRINT("hasWritten: " << Decrypt(cc, secretKey, hasWritten, 1 << L));
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
    inline std::array<std::array<server::RGSWCiphertext<T>, (uint64_t(1) << L)>, D> PlaceAtN(
        const Context::ExtendedCryptoContext<T>& cc,
        const PublicKey<T>& publicKey,
        const size_t index
    ) {
        std::array<std::array<server::RGSWCiphertext<T>, (uint64_t(1) << L)>, D> z;
        auto one  = server::Encrypt(cc, publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
        auto zero = server::Encrypt(cc, publicKey, cc->MakeCoefPackedPlaintext({ 0 }));

        for (uint32_t d = 0; d < D; d++)
            for (uint64_t slot = 0; slot < (uint64_t(1) << L); slot++)
                z[d][slot] = (slot == index) ? one : zero;

        return z;
    }
}
