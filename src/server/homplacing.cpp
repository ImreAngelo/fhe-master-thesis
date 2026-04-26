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

static RGSWCiphertext<DCRTPoly> AddRGSW(
    const Context::ExtendedCryptoContext<DCRTPoly>& cc,
    const RGSWCiphertext<DCRTPoly>& A,
    const RGSWCiphertext<DCRTPoly>& B)
{
    RGSWCiphertext<DCRTPoly> out(A.size());
    for (size_t i = 0; i < A.size(); i++)
        out[i] = cc->EvalAdd(A[i], B[i]);
    return out;
}

static RGSWCiphertext<DCRTPoly> SubRGSW(
    const Context::ExtendedCryptoContext<DCRTPoly>& cc,
    const RGSWCiphertext<DCRTPoly>& A,
    const RGSWCiphertext<DCRTPoly>& B)
{
    RGSWCiphertext<DCRTPoly> out(A.size());
    for (size_t i = 0; i < A.size(); i++)
        out[i] = cc->EvalSub(A[i], B[i]);
    return out;
}

RGSWCiphertext<DCRTPoly> Server::MultiHomPlacing(
    const Context::ExtendedCryptoContext<DCRTPoly>&                  cc,
    const PublicKey<DCRTPoly>&                                       publicKey,
    const Ciphertext<DCRTPoly>&                                      value,
    const std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&        A,
    std::vector<std::vector<Ciphertext<DCRTPoly>>>&                  L_matrix,
    std::vector<std::vector<RGSWCiphertext<DCRTPoly>>>&              I_matrix)
{
    const auto D = A.size();
    const auto L = A[0].size();
    const auto n = size_t(1) << L;
    const auto K = L_matrix[0].size();

    const auto rgswOne  = cc->EncryptRGSW(publicKey, { 1 });
    const auto rgswZero = cc->EncryptRGSW(publicKey, { 0 });

    // z[i][d] : RGSW demux indicator for the d-th chosen index at bucket i
    std::vector<std::vector<RGSWCiphertext<DCRTPoly>>> z(
        n, std::vector<RGSWCiphertext<DCRTPoly>>(D));

    for (size_t d = 0; d < D; d++) {
        // b[0] = RGSW(1), rest = RGSW(0)
        std::vector<RGSWCiphertext<DCRTPoly>> b(2*n - 1, rgswZero);
        b[0] = rgswOne;

        const auto& bits = A[d];

        for (size_t i = 0; i < L; i++) {
            const auto& c = bits[i];
            const auto idx_root = (size_t(1) << i) - 1;

            for (size_t j = 0; j < (size_t(1) << i); j++) {
                const auto idx_right = (size_t(1) << (i + 1)) + 2*j;
                const auto idx_left  = idx_right - 1;
                const auto& parent   = b[idx_root + j];

                b[idx_right] = cc->EvalInternalProduct(parent, c);
                b[idx_left]  = SubRGSW(cc, parent, b[idx_right]);
            }
        }

        for (size_t i = 0; i < n; i++) {
            z[i][d] = b[n - 1 + i];
        }
    }

    // hasWritten = RGSW(0)
    auto hasWritten = rgswZero;

    for (size_t d = 0; d < D; d++) {
        for (size_t k = 0; k < K; k++) {
            for (size_t i = 0; i < n; i++) {
                // h = z[i,d] * I[i,k] * (1 - hasWritten)     (all RGSW)
                auto zI         = cc->EvalInternalProduct(z[i][d], I_matrix[i][k]);
                auto oneMinusHW = SubRGSW(cc, rgswOne, hasWritten);
                auto h          = cc->EvalInternalProduct(zI, oneMinusHW);

                // L[i,k] += V_r ⊡ h     (RLWE += external product)
                L_matrix[i][k] = cc->EvalAdd(L_matrix[i][k], cc->EvalExternalProduct(value, h));

                // I[i,k] -= h            (RGSW subtraction)
                I_matrix[i][k] = SubRGSW(cc, I_matrix[i][k], h);

                // hasWritten += h        (RGSW addition)
                hasWritten = AddRGSW(cc, hasWritten, h);
            }
        }
    }

    return hasWritten;
}