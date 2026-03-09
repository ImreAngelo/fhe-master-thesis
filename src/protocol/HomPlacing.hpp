#pragma once
#include "openfhe.h"

namespace Server
{    
    using namespace lbcrypto;

    using CC = CryptoContext<DCRTPoly>;
    using CT = Ciphertext<DCRTPoly>;
    
    /**
     * Algorithm 1 - Homomorphic placing for one slot
     */
    std::vector<CT> HomPlacing(
        const CC context, 
        const CT value, 
        const std::vector<CT>& index_bits
    );
}