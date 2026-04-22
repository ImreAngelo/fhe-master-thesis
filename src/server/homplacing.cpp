#include "homplacing.h"

using namespace lbcrypto;


std::vector<Ciphertext<DCRTPoly>> Server::HomPlacing(const Context::ExtendedCryptoContext<DCRTPoly> &cc, const Ciphertext<DCRTPoly> &value, const std::vector<RGSWCiphertext<DCRTPoly>> &bits)
{
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

Ciphertext<DCRTPoly> Server::MultiHomPlacing(
    const Context::ExtendedCryptoContext<DCRTPoly>&              cc,
    const PublicKey<DCRTPoly>&                                   publicKey,
    const Ciphertext<DCRTPoly>&                                  value,
    const std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&    A,
    std::vector<std::vector<Ciphertext<DCRTPoly>>>&              L_matrix,
    std::vector<std::vector<Ciphertext<DCRTPoly>>>&              I_matrix)
{
    const auto D = A.size();
    const auto L = A[0].size();
    const auto n = size_t(1) << L;
    const auto K = L_matrix[0].size();

    auto ptOne  = cc->MakePackedPlaintext({1});
    auto ptZero = cc->MakePackedPlaintext({0});

    std::vector<std::vector<Ciphertext<DCRTPoly>>> z(
        n, std::vector<Ciphertext<DCRTPoly>>(D));

    for(size_t d = 0; d < D; d++) {
        // Initialize the tree: b = { 1, 0, 0, ..., 0 }
        std::vector<Ciphertext<DCRTPoly>> b(2*n - 1);
        b[0] = cc->Encrypt(publicKey, ptOne);

        const auto& bits = A[d];

        for(size_t i = 0; i < L; i++) {
            const auto& c = bits[i];
            const auto idx_root = (size_t(1) << i) - 1;

            for(size_t j = 0; j < (size_t(1) << i); j++) {
                const auto idx_right = (size_t(1) << (i + 1)) + 2*j;
                const auto idx_left  = idx_right - 1;
                const auto& parent   = b[idx_root + j];

                b[idx_right] = cc->EvalExternalProduct(parent, c);
                b[idx_left]  = cc->EvalSub(parent, b[idx_right]);
            }
        }

        for(size_t i = 0; i < n; i++) {
            z[i][d] = b[n - 1 + i];
        }
    }

    // hasWritten = 0
    auto hasWritten = cc->Encrypt(publicKey, ptZero);

    for(size_t d = 0; d < D; d++) {
        for(size_t k = 0; k < K; k++) {
            for(size_t i = 0; i < n; i++) {
                // h = z[i,d] * I[i,k] * (1 - hasWritten)
                auto zI          = cc->EvalMult(z[i][d], I_matrix[i][k]);
                auto oneMinusHW  = cc->EvalSub(ptOne, hasWritten);
                auto h           = cc->EvalMult(zI, oneMinusHW);

                // L[i,k] += h * V_r
                L_matrix[i][k] = cc->EvalAdd(L_matrix[i][k], cc->EvalMult(h, value));

                // I[i,k] -= h     (slot marked as used)
                I_matrix[i][k] = cc->EvalSub(I_matrix[i][k], h);

                // hasWritten += h
                hasWritten = cc->EvalAdd(hasWritten, h);
            }
        }
    }

    return hasWritten;
}