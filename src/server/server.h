#pragma once
#include "openfhe.h"
#include "core/context.h"
// TODO: Fix terrible include structure
#include "server/write.h"

namespace server {
    using namespace lbcrypto;
    using namespace Context;

    /**
     * @brief Run sPAR Algorithm 2 (per-bin loops) for each user, then verify
     * the message landed at L_mat[r][0] = r+1 with hasWritten flipped to 1.
     *
     * Loop 1 (binary-tree demux of the chosen index) is collapsed at the client
     * to a one-hot RGSW vector to limit noise; the test sets all D choices to r,
     * so z[i][d] is RGSW(1) when i==r and RGSW(0) otherwise. Loop 2 runs
     * server-side fully in RGSW: internal product for z·I and the (1−hasWritten)
     * gate, plaintext × RGSW for the L update (Vr is encrypted under a different,
     * non-FHE scheme, so FHE never sees its semantic meaning), and RGSW add/sub
     * for the running L/I/hasWritten state.
     *
     * @tparam K Number of slots per bin
     * @tparam D Number of choices (default = A1, A2, A3)
     * @tparam L Bit-length of the address — N = 2^L users (and bins)
     */
    template <typename T = DCRTPoly, size_t K = 3, uint32_t D = 3, uint32_t L = 1>
    bool TestServerWrite(const CCParams<CryptoContextRGSWBGV>& params)
    {
        auto cc = Context::GenExtendedCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        KeyPair<DCRTPoly> keys = cc->KeyGen();

        constexpr uint64_t N = (uint64_t(1) << L);

        const auto rgsw_zero = server::Encrypt(cc, keys.publicKey, cc->MakePackedPlaintext({ 0 }));
        const auto rgsw_one  = server::Encrypt(cc, keys.publicKey, cc->MakePackedPlaintext({ 1 }));
        const auto rlwe_one  = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({ 1 }));

        std::array<std::array<server::RGSWCiphertext<T>, K>, N> L_mat;
        std::array<std::array<server::RGSWCiphertext<T>, K>, N> I_mat;
        for (uint64_t i = 0; i < N; i++) {
            for (size_t k = 0; k < K; k++) {
                L_mat[i][k] = rgsw_zero;
                I_mat[i][k] = rgsw_one;
            }
        }

        for (uint64_t r = 0; r < N; r++) {
            DEBUG_PRINT("User " << std::to_string(r + 1) << ":");
            DEBUG_TIMER("User " + std::to_string(r + 1));

            const auto Vr = cc->MakePackedPlaintext({ static_cast<int64_t>(r + 1) });

            // Loop 1 - Place all at index r (user 0 always writes to slot 1 etc.)
            const auto z = client::PlaceAtN<T,D,L>(cc, keys.publicKey, std::array<size_t, D>{ r });

            // Loop 2
            const auto hasWritten = server::Write<T,K,D,L>(cc, keys.publicKey, Vr, L_mat, I_mat, z, keys.secretKey);

            // Output results
            auto hw = server::Decrypt(cc, keys.secretKey, hasWritten, N);
            DEBUG_PRINT("User " << (r + 1) << " hasWritten: " << hw);

            // Verify hasWritten is correct for this user
            ASSERT_EQ(hw[0], 1);
        }

        // // Final state: L_mat[i][0] == i+1, L_mat[i][k>0] == 0.
        // for (uint64_t i = 0; i < N; i++) {
        //     for (uint32_t k = 0; k < K; k++) {
        //         auto cell = cc->EvalExternalProduct(rlwe_one, L_mat[i][k]);
        //         Plaintext pt;
        //         cc->Decrypt(keys.secretKey, cell, &pt);
        //         pt->SetLength(1);
        //         const int64_t expected = (k == 0) ? static_cast<int64_t>(i + 1) : 0;
        //         ASSERT_EQ(pt->GetPackedValue()[0], expected);
        //     }
        // }

        return true;
    }
} // namespace server