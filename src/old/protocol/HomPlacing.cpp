#include "HomPlacing.hpp"
#include "fhe/include/RGSW.h"
#include "testing/Timer.h"
#include <iostream>
#include <iomanip>
#include <cmath>

#define TEST

namespace Server
{
    using namespace testing;

    // ─────────────────────────────────────────────────────────────────────────
    // Original: EvalMult-based placing
    // ─────────────────────────────────────────────────────────────────────────

    std::vector<CT> HomPlacing(const CC cc, const CT value, const std::vector<CT>& index_bits)
    {
        const uint32_t L     = index_bits.size();
        const uint32_t n     = 1u << L;
        const uint32_t total = 2 * n - 1;

        std::vector<CT> b(total);
        b[0] = value;

        Timer t("HomPlacing (EvalMult)");

        for (uint32_t i = 0; i < L; i++)
        {
            const CT& bit = index_bits[i];

            for (uint32_t j = 0; j < (1u << i); j++)
            {
                uint32_t parent_idx = (1u << i) - 1 + j;
                uint32_t left_idx   = (1u << (i + 1)) - 1 + 2 * j;
                uint32_t right_idx  = left_idx + 1;

                if (left_idx >= total || right_idx >= total)
                    throw std::out_of_range("HomPlacing: tree index overflow");

                const CT& parent = b[parent_idx];
                b[right_idx] = cc->EvalMult(parent, bit);
                b[left_idx]  = cc->EvalSub(parent, b[right_idx]);
            }
        }

        std::vector<CT> leaves(n);
        for (uint32_t i = 0; i < n; i++)
            leaves[i] = b[n - 1 + i];

        return leaves;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RGSW variant: external-product-based placing
    // ─────────────────────────────────────────────────────────────────────────

    std::vector<CT> HomPlacingRGSW(const CC cc, const CT value,
                                   const std::vector<CT>&      index_bits,
                                   const PrivateKey<DCRTPoly>& sk)
    {
        const uint32_t L     = index_bits.size();
        const uint32_t n     = 1u << L;
        const uint32_t total = 2 * n - 1;

        std::vector<CT> b(total);
        b[0] = value;

        Timer t("HomPlacingRGSW (EvalExternalProduct)");

        // Key-expansion phase: convert each RLWE(bit_i) → RGSW(bit_i).
        // This is a one-time preprocessing cost per index bit.
        std::vector<fhe::RGSWCiphertext> rgsw_bits;
        rgsw_bits.reserve(L);
        {
            Timer t_expand("  HomExpand (all bits)");
            for (const auto& bit : index_bits)
                rgsw_bits.push_back(fhe::HomExpand(cc, bit, sk));
        }

        // Tree traversal using the RGSW external product.
        {
            Timer t_tree("  Tree traversal");
            for (uint32_t i = 0; i < L; i++)
            {
                const fhe::RGSWCiphertext& rgsw_bit = rgsw_bits[i];

                for (uint32_t j = 0; j < (1u << i); j++)
                {
                    uint32_t parent_idx = (1u << i) - 1 + j;
                    uint32_t left_idx   = (1u << (i + 1)) - 1 + 2 * j;
                    uint32_t right_idx  = left_idx + 1;

                    if (left_idx >= total || right_idx >= total)
                        throw std::out_of_range("HomPlacingRGSW: tree index overflow");

                    const CT& parent = b[parent_idx];
                    b[right_idx] = fhe::EvalExternalProduct(cc, rgsw_bit, parent);
                    b[left_idx]  = cc->EvalSub(parent, b[right_idx]);
                }
            }
        }

        std::vector<CT> leaves(n);
        for (uint32_t i = 0; i < n; i++)
            leaves[i] = b[n - 1 + i];

        return leaves;
    }

} // namespace Server


// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static void printBuckets(const std::string& label,
                         const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& leaves,
                         const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
                         const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>&    sk)
{
    std::cout << label << ": ";
    for (const auto& xi : leaves)
    {
        lbcrypto::Plaintext pi;
        cc->Decrypt(sk, xi, &pi);
        pi->SetLength(1);
        std::cout << pi->GetPackedValue()[0] << " ";
    }
    std::cout << "\n";
}


// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    using namespace lbcrypto;
    using namespace testing;

#ifdef TEST
    constexpr uint32_t depth  = 3;
    constexpr int64_t  target = 6;   // target slot (binary: 110)

    // ── Shared BGV context setup ─────────────────────────────────────────────
    //
    // Both tests use the same CryptoContext so that crypto-parameter choices
    // (ring dimension, moduli, etc.) are identical and timings are comparable.
    // EvalMultKeyGen is needed only by the EvalMult variant; the RGSW variant
    // works without it but we generate it anyway to keep the setup identical.

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly>       keys;

    {
        Timer t("Setup: GenCryptoContext");
        cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
    }
    {
        Timer t("Setup: KeyGen + EvalMultKeyGen");
        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);  // needed only by HomPlacing
    }

    // Encrypt the value to be placed
    Plaintext ptValue = cc->MakePackedPlaintext({10});
    auto ctValue      = cc->Encrypt(keys.publicKey, ptValue);

    // Encrypt the L index bits  (binary encoding of target, MSB first)
    std::vector<Ciphertext<DCRTPoly>> ctBits;
    ctBits.reserve(depth);
    for (uint32_t k = 0; k < depth; k++)
    {
        int64_t bit = (target >> (depth - 1 - k)) & 1;
        ctBits.push_back(cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit})));
    }

    std::cout << "\n=== Test 1: HomPlacing (EvalMult + relinearisation) ===\n";
    {
        Timer t("Total Test 1");
        auto res = Server::HomPlacing(cc, ctValue, ctBits);
        printBuckets("Buckets", res, cc, keys.secretKey);
    }

    std::cout << "\n=== Test 2: HomPlacingRGSW (RGSW external product) ===\n";
    {
        Timer t("Total Test 2");
        auto res = Server::HomPlacingRGSW(cc, ctValue, ctBits, keys.secretKey);
        printBuckets("Buckets", res, cc, keys.secretKey);
    }

    std::cout << "\n";
#endif

    return 0;
}
