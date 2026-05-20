#include "openfhe.h"

using namespace lbcrypto;

// using RGSWCiphertext = std::vector<Ciphertext<DCRTPoly>>;

class HPSContext {
public:
    explicit HPSContext(const CryptoContext<DCRTPoly>& cc, const uint32_t ell = 1) 
        : m_params(cc), m_ell(ell)
    {};

public:
    /// @todo Convert for loop to multi-threaded in range [0..2*len)
    /// @todo Multi-layer decomposition; decompose each tower into ell digits
    std::vector<Ciphertext<DCRTPoly>> Encrypt(const PublicKey<DCRTPoly>& publicKey, const Plaintext& plaintext) const {
        const auto msg = plaintext->GetElement<DCRTPoly>();
        const auto len = m_params->GetElementParams()->GetParams().size();
        const auto zero = IsCoefPackedPlaintext(plaintext)
            ? m_params->MakeCoefPackedPlaintext({0})
            : m_params->MakePackedPlaintext({0});

        std::vector<Ciphertext<DCRTPoly>> rows;
        rows.reserve(2 * len); // * m_ell

        // Z + mG
        for(size_t col = 0; col < 2; col++) {
            for(size_t i = 0; i < len; i++) {
                auto z = m_params->Encrypt(publicKey, zero);
                z->GetElements()[col].GetAllElements()[i] += msg.GetElementAtIndex(i);
                rows.push_back(std::move(z));
            }
        }

        return rows;
    }

    /// @todo Refactor
    Ciphertext<DCRTPoly> EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const {
        const auto params = m_params->GetElementParams();
        const auto& q = params->GetParams();
        const size_t k = q.size();

        const auto& b = rlwe->GetElements()[0];
        const auto& a = rlwe->GetElements()[1];

        DCRTPoly outB(params, Format::EVALUATION, true);
        DCRTPoly outA(params, Format::EVALUATION, true);

        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(k))
        for (size_t i = 0; i < k; ++i) {
            DCRTPoly Db(params, Format::COEFFICIENT, true);
            DCRTPoly Da(params, Format::COEFFICIENT, true);

            auto bi_coef = b.GetElementAtIndex(i);  bi_coef.SetFormat(Format::COEFFICIENT);
            auto ai_coef = a.GetElementAtIndex(i);  ai_coef.SetFormat(Format::COEFFICIENT);

            for (size_t j = 0; j < k; ++j) {
                NativePoly tb(q[j], Format::COEFFICIENT, true);
                NativePoly ta(q[j], Format::COEFFICIENT, true);
                const auto qj = q[j]->GetModulus();
                for (size_t c = 0; c < bi_coef.GetLength(); ++c) {
                    tb[c] = bi_coef[c].Mod(qj);
                    ta[c] = ai_coef[c].Mod(qj);
                }
                Db.SetElementAtIndex(j, std::move(tb));
                Da.SetElementAtIndex(j, std::move(ta));
            }
            Db.SetFormat(Format::EVALUATION);
            Da.SetFormat(Format::EVALUATION);

            outB += rgsw[i    ]->GetElements()[0] * Db;
            outA += rgsw[i    ]->GetElements()[1] * Db;
            outB += rgsw[i + k]->GetElements()[0] * Da;
            outA += rgsw[i + k]->GetElements()[1] * Da;
        }

        auto result = rlwe->Clone();
        result->GetElements()[0] = std::move(outB);
        result->GetElements()[1] = std::move(outA);
        return result;
    }



protected:
    const CryptoContext<DCRTPoly>& m_params;
    const uint32_t m_ell;


// HELPER FUNCTIONS
private:
    static inline bool IsCoefPackedPlaintext(const Plaintext& plaintext) {
        return plaintext->GetEncodingType() == PlaintextEncodings::COEF_PACKED_ENCODING;
    }
    
// TEST FUNCTIONS
public: 
    DCRTPoly GadgetMultiply(const DCRTPoly& lhs, const DCRTPoly& rhs) const {
        const auto len = m_params->GetElementParams()->GetParams().size();

        DCRTPoly sum = DCRTPoly(m_params->GetElementParams(), Format::EVALUATION, true);
        for(size_t i = 0; i < len; i++) {
            sum.SetElementAtIndex(i, lhs.GetElementAtIndex(i).Times(rhs.GetElementAtIndex(i)));
        }

        return sum;
    }

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
};

TEST(BV, HPS) {
    constexpr int64_t val = 1;
    const std::vector<int64_t> value{val};

    auto params = params::Small<CryptoContextBGVRNS>();
    params.SetRingDim(16); // For printing

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    const auto keys = cc->KeyGen();

    const auto bv = HPSContext(cc);
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();

    /* Gadget Property */ {
        DCRTPoly mm = bv.GadgetMultiply(2*m, 3*m);
        ASSERT_EQ(mm, (2*m) * (3*m));
    }

    /* External Product */ {
        DEBUG_TIMER("External Product");

        const auto rgsw = bv.Encrypt(keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);

        // Right after cc->Encrypt(keys.publicKey, pt) in the test:
        const auto& rlweParams = rlwe->GetElements()[0].GetParams()->GetParams();
        const auto& ccParams   = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        std::cout << "rlwe towers: " << rlweParams.size()
                << "  cc towers: " << ccParams.size() << "\n";
        for (size_t i = 0; i < std::min(rlweParams.size(), ccParams.size()); ++i) {
            std::cout << "  i=" << i
                    << "  rlwe q_i=" << rlweParams[i]->GetModulus()
                    << "  cc q_i="   << ccParams[i]->GetModulus()
                    << (rlweParams[i]->GetModulus() == ccParams[i]->GetModulus() ? "" : "  *MISMATCH*")
                    << "\n";
        }


        const auto result = bv.EvalExternalProduct(rlwe, rgsw);

        DEBUG_PRINT("Size 2:          " << rlwe->GetElements()[0].GetParams()->GetParams().size());

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT(decrypted);
        
        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }

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
