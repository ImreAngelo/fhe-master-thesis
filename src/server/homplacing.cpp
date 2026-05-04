#include "homplacing.h"

#include <stdexcept>

using namespace lbcrypto;


std::vector<Ciphertext<DCRTPoly>> Server::HomPlacingSingle(
    const Context::ExtendedCryptoContext<DCRTPoly> &cc, 
    const Ciphertext<DCRTPoly> &value, 
    const std::vector<RGSWCiphertext<DCRTPoly>> &bits
) {
    // Levels in tree L = log(n)
    const uint64_t L = bits.size();
    const uint64_t n = uint64_t(1) << L;

    // Initialize b = { V_r, 0, 0, ..., 0 }
    std::vector<Ciphertext<DCRTPoly>> b(2*n - 1);
    b[0] = value;

    for(uint32_t i = 0; i < L; i++)
    {
        const auto& bit = bits[i];

        // Iterate over all nodes in i-th level
        for(uint64_t j = 0; j < (uint64_t(1) << i); j++)
        {
            const uint32_t idx_right = (1u << (i + 1)) + 2*j;
            const uint32_t idx_left = idx_right - 1;

            const auto& parent = b[(1u << i) - 1 + j];

            b[idx_right] = cc->EvalExternalProduct(parent, bit);
            b[idx_left] = cc->EvalSub(parent, b[idx_right]);
        }
    }

    // Output last n nodes
    std::vector<Ciphertext<DCRTPoly>> leaves(n);
    for(uint32_t i = 0; i < n; i++)
        leaves[i] = b[n - 1 + i];

    return leaves;
}

RGSWCiphertext<DCRTPoly> Server::HomPlacing(
    const Context::ExtendedCryptoContext<DCRTPoly>&,
    const PublicKey<DCRTPoly>&,
    const Ciphertext<DCRTPoly>&,
    const std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&,
    std::vector<std::vector<Ciphertext<DCRTPoly>>>&,
    std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&)
{
    throw std::runtime_error(
        "MultiHomPlacing is not yet ported to the V2 RGSW format "
        "(EvalInternalProduct is currently a stub).");
}
