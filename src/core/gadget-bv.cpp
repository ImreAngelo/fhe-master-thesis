#include "gadget-bv.h"

#include "utils/logging.h"
#include "utils/timer.h"

using namespace lbcrypto;

std::vector<DCRTPoly> bvrns::UnsignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    DEBUG_TIMER("NTT Digit Decomposition");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();
    const auto& towers = input.GetAllElements();

    // TODO: Set format
    if(input.GetFormat() != Format::EVALUATION) { DEBUG_PRINT("Plaintext was incorrect format!"); }
    
    // Output
    std::vector<DCRTPoly> g;
    g.reserve(towers.size());

    for(uint32_t i{0}; i < towers.size(); i++) {
        const auto qi{q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>()}; 
        const auto pre = (Q / BigInteger(qi)).ModInverse(qi); // TODO: Cache in context class
        
        const auto digit = input.GetElementAtIndex(i).Times(pre);

        // Project digit into all towers
        auto& row = g.emplace_back(input.GetParams(), Format::EVALUATION, true);
        auto& limbs = row.GetAllElements();
        for(uint32_t j{0}; j < towers.size(); j++) {
            const auto qj = q[j]->GetModulus();
            for(uint32_t col{0}; col < digit.GetLength(); col++) {
                limbs[j][col] = digit[col].Mod(qj);
            }
        }
    }

    return g;
}

std::vector<DCRTPoly> bvrns::SignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    DEBUG_TIMER("Coefficient Digit Decomposition");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();

    // Using centered [-q/2, q/2) representation cannot be done in EVALUATION format
    DCRTPoly input_coeff = input;
    input_coeff.SetFormat(Format::COEFFICIENT);

    std::vector<DCRTPoly> g(q.size(), DCRTPoly(input.GetParams(), Format::COEFFICIENT, true));

    // TODO: Use fast base extension?
    for (uint32_t i = 0; i < q.size(); i++) {
        const auto qi_int = q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>();
        const auto qi_half = qi_int >> 1; // TODO: Precalculate/cache "pre" in context
        const auto pre = (Q / BigInteger(q[i]->GetModulus())).ModInverse(q[i]->GetModulus()).ConvertToInt();
        
        const auto& limb = input_coeff.GetElementAtIndex(i);
        auto& row = g[i].GetAllElements();

        for (uint32_t k = 0; k < limb.GetLength(); k++) {
            auto t = limb[k].ModMul(pre, q[i]->GetModulus()).ConvertToInt<NativeInteger::SignedNativeInt>();
            auto d = (t < qi_half) ? t : t - qi_int;

            // Project signed value d into all towers j
            for (uint32_t j = 0; j < q.size(); j++) {
                const auto qj_int = q[j]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>();
                auto res = d % qj_int;
                if (res < 0) res += qj_int;
                
                row[j][k] = lbcrypto::NativeInteger(static_cast<uint64_t>(res));
            }
        }

        g[i].SetFormat(Format::EVALUATION);
    }

    return g;
}

std::vector<DCRTPoly> bvrns::PowerOfBase(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly &input)
{
    DEBUG_TIMER("Projection");

    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();
    const uint32_t num_towers = q.size();

    std::vector<DCRTPoly> P;
    P.reserve(num_towers);

    for (uint32_t j = 0; j < num_towers; j++) {
        const auto& qj = q[j]->GetModulus();
        // TODO: Cache in context
        const NativeInteger pre = (Q / BigInteger(qj)).Mod(qj).ConvertToInt();
        
        DCRTPoly component(input.GetParams(), Format::EVALUATION, true);
        
        // Only limb j will be non-zero
        const auto& current_limb = input.GetElementAtIndex(j);
        auto& limbs = component.GetAllElements(); 

        for (uint32_t col = 0; col < current_limb.GetLength(); col++) {
            limbs[j][col] = current_limb[col].ModMul(pre, qj);
        }

        P.push_back(std::move(component));
    }
    
    return P;
}
