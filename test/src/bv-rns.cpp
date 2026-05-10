#include "openfhe.h"

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
        const auto& towers = input.GetAllElements();
        const auto& q = params->GetElementParams()->GetParams();
        auto Q = params->GetElementParams()->GetModulus();
        
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
        const auto& q = params->GetElementParams()->GetParams();
        const size_t num_towers = q.size();
        auto Q = params->GetElementParams()->GetModulus();

        // Ensure we work with coefficients to check magnitudes
        DCRTPoly input_coeff = input;
        input_coeff.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> g;
        g.reserve(num_towers);

        for(uint32_t i = 0; i < num_towers; i++) {
            const auto qi = q[i]->GetModulus();
            const auto qi_half = qi >> 1;
            
            // TODO: Cache in context class
            NativeInteger pre = (Q / BigInteger(qi)).ModInverse(qi).ConvertToInt();
            NativePoly digit = input_coeff.GetElementAtIndex(i).Times(pre);

            DCRTPoly row(input.GetParams(), Format::COEFFICIENT, true);

            // 4. Center and Project into all limbs
            for(uint32_t k = 0; k < digit.GetLength(); k++) {
                NativeInteger v = digit[k]; // Value mod qi

                for(uint32_t j = 0; j < num_towers; j++) {
                    const auto qj = q[j]->GetModulus();
                    
                    if (v > qi_half) {
                        // It's "negative": conceptual value is (v - qi)
                        // Compute: (v - qi) mod qj
                        // Using: (v % qj + (qj - (qi % qj))) % qj
                        NativeInteger v_mod_qj = v.Mod(qj);
                        NativeInteger qi_mod_qj = qi.Mod(qj);
                        row.GetElementAtIndex(j)[k] = v_mod_qj.ModAdd(qj.ModSub(qi_mod_qj, qj), qj);
                    } else {
                        // It's "positive": conceptual value is v
                        row.GetElementAtIndex(j)[k] = v.Mod(qj);
                    }
                }
            }

            // 5. Convert to Evaluation (NTT) for the external product
            row.SetFormat(Format::EVALUATION);
            g.push_back(std::move(row));
        }

        return g;
    }


} // namespace standard


TEST(DECOMPOSE_B, main) {
    const std::vector<int64_t> value{3};

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();

    // Get gadget decomposition vector
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto mg = bvrns::SignedDigitDecompose(ccRNS, m);

    // Get inverse gadget vector
    // const auto md = 

    // Check inner product = m*m
    {

    }
}