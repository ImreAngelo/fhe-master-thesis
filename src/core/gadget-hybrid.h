#pragma once
#include "openfhe.h"

/**
 * @file gadget-bv.h
 * @todo move to context
 */

/// @brief BV-RNS gadget decomposition in EVALUATION format
namespace hybrid {
    using namespace lbcrypto;

    /// @brief Stays in evaluation format, but cannot use centered representation so it is much faster but also much noisier! 
    std::vector<DCRTPoly> UnsignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly& input);

    /// @brief Slower COEFFICIENT format, but less noise with centered representation
    std::vector<DCRTPoly> SignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly& input);

    /// @brief Gadget-dual of (un)signed digit decomposition
    std::vector<DCRTPoly> PowerOfBase(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly& b);

    /// @brief Encrypt a plaintext into an RGSW ciphertext 
    std::vector<Ciphertext<DCRTPoly>> Encrypt(
        const CryptoContext<DCRTPoly>& cc,
        const PublicKey<DCRTPoly>& publicKey,
        const Plaintext& plaintext
    );

    /// @brief Homomorphically evaluate the external product 
    ///        RGSW(a) x RLWE(b) = RLWE(a * b) 
    Ciphertext<DCRTPoly> EvalExternalProduct(
        const CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& rlwe,
        const std::vector<Ciphertext<DCRTPoly>>& rgsw
    );

    /// @brief Homomorphically evaluate the internal product 
    ///        RGSW(a) x RGSW(b) = RGSW(a * b) 
    std::vector<Ciphertext<DCRTPoly>> EvalInternalProduct(
        const CryptoContext<DCRTPoly>& cc,
        const std::vector<Ciphertext<DCRTPoly>>& lhs,
        const std::vector<Ciphertext<DCRTPoly>>& rhs
    );

    /// @brief Noiseless decryption (without external product) of RGSW
    DecryptResult Decrypt(
        const CryptoContext<DCRTPoly>& cc,
        const PrivateKey<DCRTPoly>& privateKey, 
        const std::vector<Ciphertext<DCRTPoly>>& ciphertext,
        Plaintext* plaintext
    );
} // namespace bvrns