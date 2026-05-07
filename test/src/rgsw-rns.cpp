#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <cmath>
#include <iostream>


using namespace lbcrypto;

namespace BV {
    template <typename T>
    using CryptoContext = typename Context::ExtendedCryptoContext<T>;

    /**
     * @brief Create the vector D_Qi(a) = ([a(Q_i/q_0)^{-1}] mod q0, ...) from page 32 (BV-RNS)
     * 
     * See Appendix B.2 of https://eprint.iacr.org/2021/204 for more details.
     */
    inline const std::vector<NativeInteger> GetGadgetElements(const CryptoContext<DCRTPoly>& cc)
    {
        // Get RNS primes q_i 
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto Q = params->GetElementParams()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();

        DEBUG_PRINT("Gadget elements: " << q.size() << " moduli");

        std::vector<lbcrypto::NativeInteger> gadgetElements;
        gadgetElements.reserve(q.size());

        // Calculate pre-computable gadget elements
        for (size_t i = 0; i < q.size(); i++) {
            auto qi = q[i]->GetModulus();
            auto div = (Q / lbcrypto::BigInteger(qi)).Mod(qi);
            auto inv = div.ModInverse(qi);

            DEBUG_PRINT("Gadget element (Q/q_" << i << ")^{-1}: " << inv);
            gadgetElements.push_back(inv);
        }

        // TODO: Store in CryptoParameters to avoid recomputation
        return gadgetElements;
    }

    /**
     * @brief Create the gadget vector D_Q(a) used in RGSW encryption from D_Q (see above) 
     */
    inline const std::vector<DCRTPoly> GetGadgetVector(const CryptoContext<DCRTPoly>& cc, const Plaintext& msg)
    {
        const auto gadgetElements = GetGadgetElements(cc);
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();

        const auto a = msg->GetElement<DCRTPoly>();
        DEBUG_PRINT("Message polynomial size: " << a.GetNumOfElements() << " moduli");

        std::vector<lbcrypto::DCRTPoly> gadgetVector;
        gadgetVector.reserve(gadgetElements.size());

        for (size_t i = 0; i < gadgetElements.size(); i++) {
            DCRTPoly poly(params->GetElementParams(), Format::EVALUATION, true);

            auto tower = a.GetElementAtIndex(i);
            auto element = tower.Times(gadgetElements[i]).Mod(q[i]->GetModulus());

            poly.SetElementAtIndex(i, element);
            gadgetVector.push_back(poly);
        }

        return gadgetVector;
    }

    /**
     * @brief Create the vector P_Qi(a) = ([a(Q_i/q_0)^{-1}] mod q0, ...) from page 32 (BV-RNS)
     * 
     * See Appendix B.2 of https://eprint.iacr.org/2021/204 for more details.
     */
    inline const std::vector<NativeInteger> GetGadgetDecompositionElements(const CryptoContext<DCRTPoly>& cc)
    {
        // Get RNS primes q_i 
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto Q = params->GetElementParams()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();

        DEBUG_PRINT("Gadget decomposition elements: " << q.size() << " moduli");

        std::vector<lbcrypto::NativeInteger> gadgetElements;
        gadgetElements.reserve(q.size());

        // Calculate pre-computable gadget elements
        for (size_t i = 0; i < q.size(); i++) {
            auto qi = q[i]->GetModulus();
            auto div = (Q / lbcrypto::BigInteger(qi)).Mod(qi);

            DEBUG_PRINT("Gadget decomposition element (Q/q_" << i << ")^{-1}: " << div);
            gadgetElements.push_back(div);
        }

        // TODO: Store in CryptoParameters to avoid recomputation
        return gadgetElements;
    }

    /**
     * @brief Create the gadget vector D_Q(a) used in RGSW encryption from D_Q (see above) 
     */
    inline const std::vector<DCRTPoly> GetGadgetDecompositionVector(const CryptoContext<DCRTPoly>& cc, const Plaintext& msg)
    {
        const auto gadgetElements = GetGadgetDecompositionElements(cc);
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

        const auto Q = params->GetElementParams()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();
        const auto a = msg->GetElement<DCRTPoly>();

        std::vector<lbcrypto::DCRTPoly> gadgetVector;
        gadgetVector.reserve(gadgetElements.size());

        for (size_t i = 0; i < gadgetElements.size(); i++) {
            DCRTPoly poly(params->GetElementParams(), Format::EVALUATION, true);
            auto element = a.GetElementAtIndex(i).Times(gadgetElements[i]).Mod(Q);
            poly.SetElementAtIndex(i, element);
            gadgetVector.push_back(poly);
        }

        return gadgetVector;
    }

    /**
     * @brief Computes the inner product of the Gadget Vector and Decomposition Vector.
     * Returns the reconstructed result as a DCRTPoly for direct verification.
     */
    inline lbcrypto::DCRTPoly InnerProduct(
        const std::vector<lbcrypto::DCRTPoly>& D_a, 
        const std::vector<lbcrypto::DCRTPoly>& P_b
    ) {
        if (D_a.empty() || D_a.size() != P_b.size()) {
            throw std::runtime_error("Vector sizes are invalid or do not match.");
        }

        // Initialize the sum using the parameters from the first element
        lbcrypto::DCRTPoly resultSum(D_a[0].GetParams(), Format::EVALUATION, true);

        for (size_t i = 0; i < D_a.size(); i++) {
            // Component-wise product and accumulation
            lbcrypto::DCRTPoly term = D_a[i] * P_b[i];
            resultSum += term;
        }

        return resultSum;
    }
}






inline CCParams<CryptoContextRGSWBGV> GetParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(3));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    params.SetNumLargeDigits(2);

    params.SetMaxRelinSkDeg(0); // Force no relinearization keys

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Test RGSW encryption, the external product and internal product
 */
inline void RunTest(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    
    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);
    
    // Get elements
    const auto mgv = BV::GetGadgetVector(cc, pt);
    const auto inv = BV::GetGadgetDecompositionVector(cc, pt);

    // Check gadget property holds
    const auto innerProduct = BV::InnerProduct(mgv, inv);
    const auto msgPoly = pt->GetElement<DCRTPoly>();

    DEBUG_PRINT("Result diff: " << (innerProduct == msgPoly));

    // const auto pt = cc->MakePackedPlaintext(innerProduct.GetElement<Poly>());
}

// Test basic functionality
TEST(RGSW_RNS_BV, b0)    { RunTest({ 0 }); }
TEST(RGSW_RNS_BV, b1)    { RunTest({ 1 }); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
