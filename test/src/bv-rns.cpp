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
        // towers[i].BaseDecompose()
        const auto& towers = input.GetAllElements();
        const auto& q = params->GetElementParams()->GetParams();

        // Q
        auto Q = params->GetElementParams()->GetModulus();
        std::cout << "Q = " << Q << std::endl;

        // Output
        std::vector<DCRTPoly> g;
        g.reserve(towers.size());

        for(uint32_t i{0}; i < towers.size(); i++) {
            std::cout << "Tower " << (i+1) << " of " << towers.size() << std::endl; 

            const auto qi{q[i]->GetModulus().ConvertToInt<NativeInteger::SignedNativeInt>()}; 
            // const auto qi_half{qi >> 1};

            auto pre = (Q / BigInteger(qi)).ModInverse(qi); // TODO: Cache in context class
            auto digit = input.GetElementAtIndex(i).Times(pre);
            
            // Multiply by base
            auto& row = g.emplace_back(input.GetParams(), Format::EVALUATION, true);
            for(uint32_t j{0}; j < towers.size(); j++) {
                row.SetElementAtIndex(j, digit);
            }
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
    m.SetFormat(Format::EVALUATION);

    // Get gadget decomposition vector
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto mg = bvrns::UnsignedDigitDecompose(ccRNS, m);

    // Get inverse gadget vector
    // const auto md = 

    // Check inner product = m*m
    {

    }
}