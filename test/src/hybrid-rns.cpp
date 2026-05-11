#include "openfhe.h"

using namespace lbcrypto;

// TODO: Move to context
namespace hybrid {
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
    DCRTPoly Decompose(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input)
    {
        DEBUG_TIMER("Decompose");

        const auto tables = InitHybridTables(cc);

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

    DCRTPoly ApproxModDown(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input) {
        DEBUG_TIMER("ApproxModDown");

        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto paramsQ = params->GetElementParams();
        const auto t = params->GetPlaintextModulus();
        return input.ApproxModDown(paramsQ, params->GetParamsP(), params->GetPInvModq(),
                params->GetPInvModqPrecon(), params->GetPHatInvModp(),
                params->GetPHatInvModpPrecon(), params->GetPHatModq(),
                params->GetModqBarrettMu(), params->GettInvModp(),
                params->GettInvModpPrecon(), t, params->GettModqPrecon());
    }
}

TEST(HYBRID, main) {
    const std::vector<int64_t> value{-2};

    const auto ps = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(ps);
    
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    const auto keys = cc->KeyGen();
    
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    
    {
        const DCRTPoly pm = hybrid::Power(cc, m);
        const DCRTPoly dm = hybrid::Decompose(cc, m);

        const DCRTPoly mult = pm * dm;

        const auto mm = hybrid::ApproxModDown(cc, mult);
        ASSERT_EQ(mm, m * m);
    }
}