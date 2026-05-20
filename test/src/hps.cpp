#include "openfhe.h"

using namespace lbcrypto;

using RGSWCiphertext = std::vector<Ciphertext<DCRTPoly>>;

class HPSContext {
public:
    explicit HPSContext(const CryptoContext<DCRTPoly>& cc, const usint ell = 1) 
        : m_params(cc)
    {};

// protected:
public:
    /// @todo Assert eval mode
    std::vector<DCRTPoly> Decompose(const DCRTPoly& input) const {
        const auto& q = m_params->GetElementParams()->GetParams();

        DCRTPoly zero(input.GetParams(), Format::EVALUATION, true);
        std::vector<DCRTPoly> d(q.size(), zero);

        for (size_t i = 0; i < q.size(); i++) {
            d[i].SetElementAtIndex(i, input.GetElementAtIndex(i));
        }

        return d;
    }

private:
    const CryptoContext<DCRTPoly>& m_params;
};

TEST(BV, HPS) {
    constexpr int64_t val = 1;
    const std::vector<int64_t> value{val};

    auto params = params::Small<CryptoContextBGVRNS>(3);
    params.SetRingDim(16); // For printing

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    const auto keys = cc->KeyGen();

    const auto bv = HPSContext(cc, 2); // at level 1:  2 -> 1, 4 -> 2, 8 -> 3
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();

    /* Gadget Property */ {
        const auto dm = bv.Decompose(m);
        const auto pm = bv.Decompose(m);

        ASSERT_EQ(dm.size(), pm.size()) << "Size mismatch between P(m) and D(m)";

        DCRTPoly mm = dm[0] * pm[0];

        for(uint32_t i = 1; i < dm.size(); i++) {
            mm += dm[i] * pm[i];
        }

        ASSERT_EQ(mm, m * m);
    }

    // /* External Product */ {
    //     DEBUG_TIMER("External Product");

    //     const auto rgsw = bv.Encrypt(keys.publicKey, pt);
    //     const auto rlwe = cc->Encrypt(keys.publicKey, pt);

    //     const auto result = bv.EvalExternalProduct(rlwe, rgsw);

    //     Plaintext decrypted;
    //     cc->Decrypt(keys.secretKey, result, &decrypted);
    //     decrypted->SetLength(1);

    //     DEBUG_PRINT(decrypted);
        
    //     const auto expected = cc->MakeCoefPackedPlaintext({val * val});
    //     ASSERT_EQ(decrypted, expected);
    // }

    // /* Internal Product */ {
    //     DEBUG_TIMER("Internal Product");

    //     const auto rgsw = bv.Encrypt(keys.publicKey, pt);
    //     const auto prod = bv.EvalInternalProduct(rgsw, rgsw);

    //     const auto one = cc->MakeCoefPackedPlaintext({1});
    //     const auto identity = cc->Encrypt(keys.publicKey, one);
    //     const auto result = bv.EvalExternalProduct(identity, prod);

    //     Plaintext decrypted;
    //     cc->Decrypt(keys.secretKey, result, &decrypted);
    //     decrypted->SetLength(1);

    //     DEBUG_PRINT(decrypted);
    // }

    // /* Depth */ {
    //     const int64_t t = params.GetPlaintextModulus();

    //     // RGSW(3): the fixed multiplier applied each round.
    //     const auto mult = 1;
    //     const auto pt3   = cc->MakeCoefPackedPlaintext({mult});
    //     const auto rgsw2 = bv.Encrypt(keys.publicKey, pt3);

    //     // val = RGSW(1) initially; RLWE(1) used as the left operand for verification.
    //     const auto pt1   = cc->MakeCoefPackedPlaintext({1});
    //     const auto rlwe1 = cc->Encrypt(keys.publicKey, pt1);
    //     auto val         = bv.Encrypt(keys.publicKey, pt1);

    //     // 2^n mod t, kept centered in (-t/2, t/2].
    //     int64_t expected = 1;

    //     for (int n = 1; n <= 64; ++n) {
    //         val      = bv.EvalInternalProduct(rgsw2, val);
    //         expected = (expected * mult) % t;
    //         if (expected > t / 2) expected -= t;

    //         const auto res = bv.EvalExternalProduct(rlwe1, val);
    //         Plaintext decrypted;
    //         cc->Decrypt(keys.secretKey, res, &decrypted);
            
    //         decrypted->SetLength(4);
    //         std::cout << n << ":\t" << decrypted << std::endl;

    //         const auto& coef = decrypted->GetCoefPackedValue();
    //         const int64_t got = coef.empty() ? 0 : coef[0];

    //         if (got != expected) {
    //             std::cout << "Chained internal products valid up to depth " << (n - 1) << std::endl;
    //             return;
    //         }
    //     }
    // }
}
