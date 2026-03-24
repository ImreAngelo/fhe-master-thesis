#pragma once
#include "openfhe.h"
#include "fhe/include/RGSW.h"

namespace client 
{
    using namespace lbcrypto;
    using namespace fhe;

    /**
     * Takes an RLWE ciphertext and expands it into an RGSW ciphertext
     * The RGSW ciphertext is used in HomPlacing.cpp 
     */
    RGSWCiphertext HomExpand(
        const CryptoContext<DCRTPoly>&  cryptoContext,
        const Ciphertext<DCRTPoly>&     ciphertext
    );
}