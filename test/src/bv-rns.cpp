#include "openfhe.h"
#include "utils/timer.h"

using namespace lbcrypto;

/**
 * @brief BV-RNS gadget decomposition
 */
namespace bvrns {
    /// @brief Stays in evaluation format, but cannot use centered representation 
    //         so it is much faster but also much noisier! 
    std::vector<DCRTPoly> UnsignedDigitDecompose(
        const std::shared_ptr<CryptoParametersRNS> params, 
        const DCRTPoly& input
    ) {
        DEBUG_TIMER("NTT Digit Decomposition");

        const auto& Q = params->GetElementParams()->GetModulus();
        const auto& q = params->GetElementParams()->GetParams();
        const auto& towers = input.GetAllElements();
        
        // Output
        std::vector<DCRTPoly> g;
        g.reserve(towers.size());

        for(uint32_t i{0}; i < towers.size(); i++) {
            const auto qi{q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>()}; 
            const auto pre = (Q / BigInteger(qi)).ModInverse(qi); // TODO: Cache in context class
            
            const auto digit = input.GetElementAtIndex(i).Times(pre);
            
            // Multiply by base
            auto& row = g.emplace_back(input.GetParams(), Format::EVALUATION, true);
            for(uint32_t j{0}; j < towers.size(); j++) {
                row.SetElementAtIndex(j, digit);
            }
        }

        return g;
    }

    /// @brief Slower COEFFICIENT format, but less noise with centered representation
    std::vector<DCRTPoly> SignedDigitDecompose(
        const std::shared_ptr<CryptoParametersRNS> params, 
        const DCRTPoly& input
    ) {
        DEBUG_TIMER("Coefficient Digit Decomposition");

        const auto& Q = params->GetElementParams()->GetModulus();
        const auto& q = params->GetElementParams()->GetParams();

        // Using centered [-q/2, q/2) representation cannot be done in EVALUATION format
        DCRTPoly input_coeff = input;
        input_coeff.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> g(q.size(), DCRTPoly(input.GetParams(), Format::COEFFICIENT, true));

        for (uint32_t i = 0; i < q.size(); i++) {
            const auto qi_int = q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>();
            const auto qi_half = qi_int >> 1;
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


} // namespace standard


TEST(DECOMPOSE_B, main) {
    const std::vector<int64_t> value{-2};

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    // Get gadget decomposition vector
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

    /* NTT Format */ 
    {
        const auto mg = bvrns::UnsignedDigitDecompose(ccRNS, m);
        // for(const auto& l : mg) DEBUG_PRINT(l);
    }

    /* Coefficient */
    {
        const auto mg = bvrns::SignedDigitDecompose(ccRNS, m);
        // for(const auto& l : mg) DEBUG_PRINT(l);
    }

    // Get inverse gadget vector
    // const auto md = 

    // Check inner product = m*m
    {

    }
}