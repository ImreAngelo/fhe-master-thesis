#include "core/include/context.h"
#include "core/include/helpers.h"
#include "core/include/params.h"
#include "client/include/rgsw.h"

using namespace lbcrypto;

TEST(RGSW, NegS) {
    const uint32_t ell = 4;
    const uint64_t B   = 2;

    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);
    params.SetMaxRelinSkDeg(3);
    params.SetGadgetLevels(ell);
    params.SetGadgetBase(B);

    auto cc = Server::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();

    CryptoContext<DCRTPoly> cc_ctx = cc;
    auto rgsw = Client::CreateRGSW_NegS(cc_ctx, keys, ell, B);
    ASSERT_EQ(rgsw.size(), size_t{2 * ell});

    const uint32_t ring_dim = cc->GetRingDimension();
    const uint64_t t        = cc->GetCryptoParameters()->GetPlaintextModulus();
    NativeInteger t_nat(t);

    // Ground truth: NTT(-s) per slot, in [0, t)
    auto sk_poly = keys.secretKey->GetPrivateElement();
    sk_poly.SetFormat(Format::EVALUATION);
    auto& sk_eval = sk_poly.GetElementAtIndex(0);

    std::vector<uint64_t> neg_s(ring_dim);
    for (uint32_t i = 0; i < ring_dim; i++) {
        NativeInteger v = sk_eval[i];
        neg_s[i] = (v == NativeInteger(0)) ? 0 : (t_nat - v).ConvertToInt<uint64_t>();
    }

    for (uint32_t k = 0; k < ell; k++) {
        SCOPED_TRACE("k=" + std::to_string(k));

        // B^{-(k+1)} mod t
        NativeInteger Bk(1);
        for (uint32_t j = 0; j <= k; j++)
            Bk = Bk.ModMul(NativeInteger(B), t_nat);
        NativeInteger Bk_inv = Bk.ModInverse(t_nat);

        // Center a value in [0, t) to [-t/2, t/2]
        auto center = [&](uint64_t v) -> int64_t {
            int64_t c = static_cast<int64_t>(v);
            if (c > static_cast<int64_t>(t / 2)) c -= static_cast<int64_t>(t);
            return c;
        };

        // Top half row k: each slot i should decrypt to center(-s[i] * B^{-(k+1)} mod t)
        {
            Plaintext pt;
            cc->Decrypt(keys.secretKey, rgsw[k], &pt);
            pt->SetLength(ring_dim);
            const auto& vals = pt->GetPackedValue();

            SCOPED_TRACE("top");
            for (uint32_t i = 0; i < ring_dim; i++) {
                int64_t expected = center(
                    NativeInteger(neg_s[i]).ModMul(Bk_inv, t_nat).ConvertToInt<uint64_t>()
                );
                ASSERT_EQ(vals[i], expected) << "slot " << i;
            }
        }

        // Bottom half row k: every slot should decrypt to center(B^{-(k+1)} mod t)
        {
            Plaintext pt;
            cc->Decrypt(keys.secretKey, rgsw[k + ell], &pt);
            pt->SetLength(ring_dim);
            const auto& vals = pt->GetPackedValue();

            int64_t expected = center(Bk_inv.ConvertToInt<uint64_t>());
            SCOPED_TRACE("bottom");
            for (uint32_t i = 0; i < ring_dim; i++) {
                ASSERT_EQ(vals[i], expected) << "slot " << i;
            }
        }
    }

    
}
