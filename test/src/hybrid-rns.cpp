#include "openfhe.h"

using namespace lbcrypto;

// TODO: Move to context
namespace hybrid {
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
    /// @todo Use FastBaseExtension instead of exact
    DCRTPoly Decompose(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input)
    {
        DEBUG_TIMER("Decompose");

        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto QP = params->GetParamsQP();
        const auto& Q_params = params->GetElementParams()->GetParams();
        const auto& P_params = params->GetParamsP()->GetParams();
        const auto Q_mod = params->GetElementParams()->GetModulus();

        DCRTPoly inputCoeff = input;
        inputCoeff.SetFormat(Format::COEFFICIENT);

        DCRTPoly result(QP, Format::COEFFICIENT, true);
        auto& res_limbs = result.GetAllElements();
        const auto& in_limbs = inputCoeff.GetAllElements();

        for(uint32_t i = 0; i < in_limbs.size(); i++) {
            res_limbs[i] = in_limbs[i];
        }

        std::vector<NativePoly> v(in_limbs.size());
        for(uint32_t i = 0; i < in_limbs.size(); i++) {
            const auto& qi = Q_params[i]->GetModulus();
            NativeInteger inv = (Q_mod / BigInteger(qi)).ModInverse(qi).ConvertToInt();
            v[i] = in_limbs[i].Times(inv);
        }

        for(uint32_t j = 0; j < P_params.size(); j++) {
            const auto& pj = P_params[j]->GetModulus();
            uint32_t target_idx = in_limbs.size() + j;

            for(uint32_t i = 0; i < in_limbs.size(); i++) {
                const auto& qi = Q_params[i]->GetModulus();
                NativeInteger q_hat_i_mod_pj = (Q_mod / BigInteger(qi)).Mod(pj).ConvertToInt();

                for(uint32_t col = 0; col < res_limbs[target_idx].GetLength(); col++) {
                    NativeInteger term = v[i][col].ModMul(q_hat_i_mod_pj, pj);
                    res_limbs[target_idx][col] = res_limbs[target_idx][col].ModAdd(term, pj);
                }
            }
        }

        result.SetFormat(Format::EVALUATION);
        return result;
    }

    DCRTPoly ApproxModDown(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& input) {
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

DCRTPoly EvalInnerProduct(
    const std::vector<DCRTPoly>& D, 
    const std::vector<DCRTPoly>& P
) {
    // TODO: Ensure we are in EVALUATION format
    if (D.size() != P.size() || D.size() == 0) {
        throw std::runtime_error("Vector dimensions must match and be non-zero");
    }

    DCRTPoly result = D[0] * P[0];

    for (size_t i = 1; i < D.size(); i++) {
        result += (D[i] * P[i]);
    }

    return result;
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