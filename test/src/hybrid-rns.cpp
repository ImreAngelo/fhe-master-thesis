#include "openfhe.h"

using namespace lbcrypto;

// TODO: Move everything to context class
namespace hybrid {
    /// @todo Store in context 
    struct HybridTables {
        std::shared_ptr<typename DCRTPoly::Params> paramsQP;
        std::shared_ptr<typename DCRTPoly::Params> paramsQ;
        std::shared_ptr<typename DCRTPoly::Params> paramsP;
        
        // Decompose-tabeller (Q -> P)
        std::vector<NativeInteger> qInv;              // [(Q/qi)^-1] mod qi
        std::vector<std::vector<NativeInteger>> qHatModP; // [(Q/qi)] mod pj
        
        // ScaleDown-tabeller (QP -> Q)
        std::vector<NativeInteger> pInvModq;          // [P^-1] mod qi
    };

    /// @todo Store in context 
    HybridTables InitHybridTables(const CryptoContext<DCRTPoly>& cc) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        
        HybridTables tables;
        tables.paramsQP = params->GetParamsQP();
        tables.paramsQ  = params->GetElementParams();
        tables.paramsP  = params->GetParamsP();

        const auto& Q_limbs = tables.paramsQ->GetParams();
        const auto& P_limbs = tables.paramsP->GetParams();
        const auto Q_mod = tables.paramsQ->GetModulus();
        const auto P_mod = tables.paramsP->GetModulus();

        uint32_t numQ = Q_limbs.size();
        uint32_t numP = P_limbs.size();

        tables.qInv.resize(numQ);
        tables.qHatModP.resize(numQ, std::vector<NativeInteger>(numP));
        tables.pInvModq.resize(numQ);

        for (uint32_t i = 0; i < numQ; i++) {
            const auto& qi = Q_limbs[i]->GetModulus();
            BigInteger qHat = Q_mod / BigInteger(qi);
            
            tables.qInv[i] = qHat.ModInverse(qi).ConvertToInt();
            tables.pInvModq[i] = P_mod.ModInverse(qi).ConvertToInt();

            for (uint32_t j = 0; j < numP; j++) {
                const auto& pj = P_limbs[j]->GetModulus();
                tables.qHatModP[i][j] = qHat.Mod(pj).ConvertToInt();
            }
        }
        return tables;
    }

    /// @brief Scales the input m by P,
    /// embedding the message into a larger space: Q -> QP
    DCRTPoly Power(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input) 
    {
        DEBUG_TIMER("Power");

        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto QP = params->GetParamsQP();
        const auto P = params->GetParamsP()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();

        DCRTPoly m(QP, Format::EVALUATION, true);
        
        const auto& inputLimb = input.GetAllElements();
        auto& limbs = m.GetAllElements();
        
        for(uint32_t k = 0; k < q.size(); k++) {
            const auto& qk = q[k]->GetModulus();
            NativeInteger pMod = P.Mod(qk).ConvertToInt();

            // Multiply the k-th limb by (P mod qk)
            for(uint32_t col = 0; col < inputLimb[k].GetLength(); col++) {
                limbs[k][col] = inputLimb[k][col].ModMul(pMod, qk);
            }
        }

        // Note: the last limb(s) are mod p_i and so are always 0, therefore skip them
        return m;
    }

    /// @brief Base extension/lift Q -> QP
    DCRTPoly Decompose(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input, const HybridTables& tables)
    {
        DEBUG_TIMER("Decompose");

        // Coefficient mode required?
        DCRTPoly result(tables.paramsQP, Format::COEFFICIENT, true);
        DCRTPoly inputCoeff = input;
        inputCoeff.SetFormat(Format::COEFFICIENT);

        const auto& in_limbs = inputCoeff.GetAllElements();
        auto& res_limbs = result.GetAllElements();
        
        uint32_t numQ = in_limbs.size();
        uint32_t numP = tables.paramsP->GetParams().size();
        uint32_t n = tables.paramsQ->GetRingDimension();

        // Copy Q-towers (O(L*N)) and pre-scale by qInv
        // (saves cache-accesses)
        std::vector<NativePoly> v(numQ);
        for(uint32_t i = 0; i < numQ; i++) {
            res_limbs[i] = in_limbs[i];
            v[i] = in_limbs[i].Times(tables.qInv[i]);
        }

        // Fast Base Extension (Q -> QP)
        // TODO: Re-enable multi-threading
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numP))
        for(uint32_t j = 0; j < numP; j++) {
            uint32_t target_idx = numQ + j;
            const auto& pj = tables.paramsP->GetParams()[j]->GetModulus();
            auto& target_poly = res_limbs[target_idx];

            for(uint32_t i = 0; i < numQ; i++) {
                const auto& qHat = tables.qHatModP[i][j];
                const auto& source_poly = v[i];

                for(uint32_t col = 0; col < n; col++) {
                    // Fused Multiply-Add: res = (res + source * qHat) mod pj
                    NativeInteger term = source_poly[col].ModMul(qHat, pj);
                    target_poly[col] = target_poly[col].ModAdd(term, pj);
                }
            }
        }

        result.SetFormat(Format::EVALUATION);
        return result;
    }

    /// @brief Thin wrapper around OpenFHE's ApproxModDown 
    DCRTPoly ApproxModDown(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input) {
        DEBUG_TIMER("ApproxModDown");

        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto paramsQ = params->GetElementParams();
        const NativeInteger t = params->GetPlaintextModulus();
        return input.ApproxModDown(paramsQ, params->GetParamsP(), params->GetPInvModq(),
                params->GetPInvModqPrecon(), params->GetPHatInvModp(),
                params->GetPHatInvModpPrecon(), params->GetPHatModq(),
                params->GetModqBarrettMu(), params->GettInvModp(),
                params->GettInvModpPrecon(), t, params->GettModqPrecon());
    }

    /// @brief Encrypt RGSW ciphertext
    /// @todo Refactor -> manual encryption in QP with DGG/DUG
    std::vector<Ciphertext<DCRTPoly>> Encrypt(
        const CryptoContext<DCRTPoly>& cc, const HybridTables& tables, 
        const PublicKey<DCRTPoly>& publicKey, const Plaintext& m
    ) {
        DEBUG_TIMER("Encrypt RGSW");

        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto paramsQP = params->GetParamsQP();

        // Scale by P
        DCRTPoly mPoly = m->GetElement<DCRTPoly>();
        DCRTPoly mP = Power(cc, mPoly);

        std::vector<Ciphertext<DCRTPoly>> rgsw;
        for(size_t i = 0; i < 2; i++) {
            // TODO: This contains no noise!!! (not secure in production)
            DCRTPoly c0(paramsQP, Format::EVALUATION, true);
            DCRTPoly c1(paramsQP, Format::EVALUATION, true);
            
            auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(cc);
            ct->SetElements({c0, c1});
            rgsw.push_back(ct);
        }

        // Z + mG = Z + P(m) in hybrid
        rgsw[0]->GetElements()[0] += mP;
        rgsw[1]->GetElements()[1] += mP;

        return rgsw;
    }

    /// @brief External Product
    Ciphertext<DCRTPoly> EvalExternalProduct(
        const CryptoContext<DCRTPoly>& cc, const HybridTables& tables,
        const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw
    ) {
        auto c = rlwe->GetElements();
        c[0].SetFormat(Format::EVALUATION);
        c[1].SetFormat(Format::EVALUATION);

        const auto d0 = Decompose(cc, c[0], tables);
        const auto d1 = Decompose(cc, c[1], tables);

        DCRTPoly out0(tables.paramsQP, Format::EVALUATION, true);
        DCRTPoly out1(tables.paramsQP, Format::EVALUATION, true);

        // Rad 0 (multipliseres med d0)
        out0 += (d0 * rgsw[0]->GetElements()[0]);
        out1 += (d0 * rgsw[0]->GetElements()[1]);
        out0 += (d1 * rgsw[1]->GetElements()[0]);
        out1 += (d1 * rgsw[1]->GetElements()[1]);

        auto result = rlwe->Clone();
        result->GetElements()[0] = ApproxModDown(cc, out0);
        result->GetElements()[1] = ApproxModDown(cc, out1);

        return result;
    }
}

TEST(HYBRID, main) {
    const std::vector<int64_t> value{2};

    const auto ps = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(ps);
    
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    const auto keys = cc->KeyGen();
    
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    const auto tables = hybrid::InitHybridTables(cc); // TODO: Move to context
    
    const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    ASSERT_EQ(params->GetPlaintextModulus(), 1 << 8);

    // Gadget Property
    {
        const DCRTPoly m = pt->GetElement<DCRTPoly>();

        const DCRTPoly pm = hybrid::Power(cc, m);
        const DCRTPoly dm = hybrid::Decompose(cc, m, tables);

        const DCRTPoly mult = pm * dm;

        const auto mm = hybrid::ApproxModDown(cc, mult);
        ASSERT_EQ(mm, m * m);
    }

    // External Product
    {
        const auto rgsw = hybrid::Encrypt(cc, tables, keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);
        const auto ext = hybrid::EvalExternalProduct(cc, tables, rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, ext, &decrypted);
        decrypted->SetLength(value.size());

        DEBUG_PRINT("External Product: " << decrypted);

        const auto expected = cc->MakeCoefPackedPlaintext({value[0] * value[0]});
        ASSERT_EQ(decrypted, expected);
    }
}