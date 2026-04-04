#pragma once
#include "openfhe.h"
#include "key/privatekey.h"

namespace Server
{
    using namespace lbcrypto;

    using CC = CryptoContext<DCRTPoly>;
    using CT = Ciphertext<DCRTPoly>;

    /**
     * Algorithm 1 - Homomorphic placing using EvalMult + relinearisation.
     * Requires EvalMultKeyGen to have been called on cc.
     */
    std::vector<CT> HomPlacing(
        const CC cc,
        const CT value,
        const std::vector<CT>& index_bits
    );

    /**
     * Algorithm 1 - Homomorphic placing using RGSW external product.
     * Avoids EvalMultKeyGen: index_bits are expanded into RGSW ciphertexts
     * internally via HomExpand (requires sk for key expansion).
     */
    std::vector<CT> HomPlacingRGSW(
        const CC cc,
        const CT value,
        const std::vector<CT>& index_bits,
        const PrivateKey<DCRTPoly>& sk
    );
}
