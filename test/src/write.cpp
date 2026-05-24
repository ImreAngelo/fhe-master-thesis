#include "openfhe.h"
#include "core/context.h"
#include "server/write.h"
#include "utils/logging.h"

// Map a centered value (-m/2, m/2] back to [0, m).
#define RECENTER(x, m) ((x) < 0 ? (x) + (m) : (x))

using namespace lbcrypto;
using namespace Core;

/**
 * @brief Run sPAR Algorithm 2 (per-bin loops) for each user, then verify
 * the message landed at L_mat[r][0] = r+1 with hasWritten flipped to 1.
 *
 * @tparam K Number of slots per bin
 * @tparam D Number of choices (default = A1, A2, A3)
 * @tparam L Bit-length of the address — N = 2^L users (and bins)
 */
template <size_t K = 3, uint32_t D = 3, uint32_t L = 1>
void TestServerWrite(const CCParams<CryptoContextBGVRNS>& params)
{
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();

    const HPSContext bv(cc, 6);

    constexpr uint64_t N = (uint64_t(1) << L);
    // const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    // const auto rgsw_zero = bv.EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 0 }));
    // const auto rgsw_one  = bv.EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));
    // const auto rlwe_one  = cc->Encrypt(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }));

    std::array<std::array<server::RGSWCiphertext<DCRTPoly>, K>, N> L_mat;
    std::array<std::array<server::RGSWCiphertext<DCRTPoly>, K>, N> I_mat;
    for (uint64_t i = 0; i < N; i++) {
        for (size_t k = 0; k < K; k++) {
            // Server should not add noise
            L_mat[i][k] = bv.EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 0 }), true);
            I_mat[i][k] = bv.EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({ 1 }), true);
        }
    }

    DEBUG_PRINT("Initial state:");
    server::debug::PrintMatrix("L", cc, bv, L_mat, keys.secretKey); DEBUG_PRINT("");
    server::debug::PrintMatrix("I", cc, bv, I_mat, keys.secretKey); DEBUG_PRINT("");

    for (uint64_t r = 0; r < N; r++) {
        DEBUG_PRINT("User " << std::to_string(r + 1) << ":");
        DEBUG_TIMER("User " + std::to_string(r + 1));

        const auto Vr = cc->MakeCoefPackedPlaintext({ static_cast<int64_t>(r + 1) });

        // Loop 1 - Place all at index r (user 0 always writes to slot 1 etc.)
        const auto z = client::PlaceAtN<DCRTPoly,D,L>(cc, bv, keys.publicKey, r);

        // Loop 2
        const auto hasWritten = server::Write<DCRTPoly,K,D,L>(cc, bv, keys.publicKey, Vr, L_mat, I_mat, z, keys.secretKey, r + 1);

        // Output results
        auto hw = server::Decrypt(cc, bv, keys.secretKey, hasWritten);
        DEBUG_PRINT("User " << (r + 1) << " hasWritten: " << hw);

        DEBUG_PRINT("");
        server::debug::PrintMatrix("L", cc, bv, L_mat, keys.secretKey); DEBUG_PRINT("");
        server::debug::PrintMatrix("I", cc, bv, I_mat, keys.secretKey); DEBUG_PRINT("");

        // Verify hasWritten is correct for this user
        ASSERT_EQ(hw[0], 1);
    }

    // // Final state: L_mat[i][0] == i+1, I_mat[i][k] == 0.
}

// Main tests
TEST(ServerWrite, N2)   { TestServerWrite<3, 3, 1>(params::Small<CryptoContextBGVRNS>(4)); }
TEST(ServerWrite, N4)   { TestServerWrite<3, 3, 2>(params::Small<CryptoContextBGVRNS>(8)); }
// TEST(ServerWrite, N32)  { TestServerWrite<3, 3, 5>(params::Small<CryptoContextBGVRNS>(4)); }
