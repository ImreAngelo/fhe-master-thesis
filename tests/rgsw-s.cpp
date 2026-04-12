#pragma once

#include "openfhe.h"

#include <vector>
#include <stdint.h>

using namespace lbcrypto;
using RGSWCiphertext = std::vector<Ciphertext<DCRTPoly>>;

void TestRGSW_NegS(
    CryptoContext<DCRTPoly>& cc,
    KeyPair<DCRTPoly>& keys,
    const RGSWCiphertext& rgsw,
    uint32_t ell,
    uint64_t B)
{
    uint32_t ring_dim = cc->GetRingDimension();
    uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();
    NativeInteger t_nat(t);

    // Extract ground truth: NTT(-s) slot values
    auto sk_poly = keys.secretKey->GetPrivateElement();
    sk_poly.SetFormat(Format::EVALUATION);
    auto& sk_eval = sk_poly.GetElementAtIndex(0);

    std::vector<int64_t> neg_s_slots(ring_dim);
    for (uint32_t i = 0; i < ring_dim; i++) {
        NativeInteger v = sk_eval[i];
        NativeInteger neg_v = (v == NativeInteger(0)) ? NativeInteger(0) : t_nat - v;
        int64_t c = static_cast<int64_t>(neg_v.ConvertToInt<uint64_t>());
        if (c > static_cast<int64_t>(t / 2)) c -= static_cast<int64_t>(t);
        neg_s_slots[i] = c;
    }

    bool all_pass = true;

    for (uint32_t k = 0; k < ell; k++) {
        // Compute B^{-(k+1)} centered
        NativeInteger Bk(1), B_nat(B);
        for (uint32_t j = 0; j <= k; j++)
            Bk = Bk.ModMul(B_nat, t_nat);
        NativeInteger Bk_inv = Bk.ModInverse(t_nat);
        int64_t bk_inv_c = static_cast<int64_t>(Bk_inv.ConvertToInt<uint64_t>());
        if (bk_inv_c > static_cast<int64_t>(t / 2)) bk_inv_c -= static_cast<int64_t>(t);

        // ── Test top half row k: should decrypt to -s * B^{-(k+1)} ──────
        Plaintext pt_top;
        cc->Decrypt(keys.secretKey, rgsw[k], &pt_top);
        pt_top->SetLength(ring_dim);
        auto& top_vals = pt_top->GetPackedValue();

        bool top_pass = true;
        for (uint32_t i = 0; i < ring_dim; i++) {
            // Expected: neg_s_slots[i] * bk_inv_c mod t, centered
            int64_t expected = static_cast<int64_t>(
                NativeInteger(
                    (neg_s_slots[i] < 0)
                        ? static_cast<uint64_t>(neg_s_slots[i] + t)
                        : static_cast<uint64_t>(neg_s_slots[i])
                ).ModMul(Bk_inv, t_nat).ConvertToInt<uint64_t>()
            );
            if (expected > static_cast<int64_t>(t / 2)) expected -= static_cast<int64_t>(t);

            if (top_vals[i] != expected) {
                std::cout << "FAIL top row k=" << k
                          << " slot=" << i
                          << " got=" << top_vals[i]
                          << " expected=" << expected << "\n";
                top_pass = false;
                break;
            }
        }
        std::cout << "Top row k=" << k << ": " << (top_pass ? "PASS" : "FAIL") << "\n";
        all_pass &= top_pass;

        // ── Test bottom half row k: should decrypt to B^{-(k+1)} everywhere ──
        Plaintext pt_bot;
        cc->Decrypt(keys.secretKey, rgsw[k + ell], &pt_bot);
        pt_bot->SetLength(ring_dim);
        auto& bot_vals = pt_bot->GetPackedValue();

        bool bot_pass = true;
        for (uint32_t i = 0; i < ring_dim; i++) {
            if (bot_vals[i] != bk_inv_c) {
                std::cout << "FAIL bottom row k=" << k
                          << " slot=" << i
                          << " got=" << bot_vals[i]
                          << " expected=" << bk_inv_c << "\n";
                bot_pass = false;
                break;
            }
        }
        std::cout << "Bottom row k=" << k << ": " << (bot_pass ? "PASS" : "FAIL") << "\n";
        all_pass &= bot_pass;
    }

    std::cout << "\nRGSW(-s) test: " << (all_pass ? "ALL PASS" : "FAILED") << "\n";
}


namespace core::server {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    // /**
    //  * 
    //  */
    // RGSWCiphertext<DCRTPoly> EncryptRGSW(
    //     CryptoContext<DCRTPoly>& cc,
    //     KeyPair<DCRTPoly>& keys,
    //     Plaintext& msg,
    //     uint32_t l,
    //     uint64_t B = 2
    // ) {
    //     uint32_t N = cc->GetRingDimension();
    //     uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();
    //     NativeInteger t_nat(t);

    //     assert(msg.size() <= ring_dim);       
    // }

    RGSWCiphertext<DCRTPoly> CreateRGSW_NegS(
        CryptoContext<DCRTPoly>& cc,
        KeyPair<DCRTPoly>& keys,
        uint32_t ell,
        uint64_t B)
    {
        uint32_t ring_dim = cc->GetRingDimension();
        uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();
        NativeInteger t_nat(t);

        // Get secret key in EVALUATION format — these ARE the NTT slot values
        auto sk_poly = keys.secretKey->GetPrivateElement();
        sk_poly.SetFormat(Format::EVALUATION);
        auto& sk_eval = sk_poly.GetElementAtIndex(0);  // first RNS limb

        RGSWCiphertext<DCRTPoly> result(2 * ell);

        for (uint32_t k = 0; k < ell; k++) {
            // Compute B^{-(k+1)} mod t
            NativeInteger Bk(1), B_nat(B);
            for (uint32_t j = 0; j <= k; j++)
                Bk = Bk.ModMul(B_nat, t_nat);
            NativeInteger Bk_inv = Bk.ModInverse(t_nat);

            // ── Top half: packed slots = NTT(-s) * B^{-(k+1)} ────────────────
            std::vector<int64_t> neg_s_slots(ring_dim);
            for (uint32_t i = 0; i < ring_dim; i++) {
                NativeInteger v = sk_eval[i];
                // Negate: (-s) mod t
                NativeInteger neg_v = (v == NativeInteger(0))
                    ? NativeInteger(0)
                    : t_nat - v;
                // Scale by B^{-(k+1)}
                NativeInteger scaled = neg_v.ModMul(Bk_inv, t_nat);
                int64_t c = static_cast<int64_t>(scaled.ConvertToInt<uint64_t>());
                if (c > static_cast<int64_t>(t / 2)) c -= static_cast<int64_t>(t);
                neg_s_slots[i] = c;
            }
            auto pt_neg_s = cc->MakePackedPlaintext(neg_s_slots);
            result[k] = cc->Encrypt(keys.publicKey, pt_neg_s);

            // ── Bottom half: NTT(B^{-(k+1)}) = constant vector ───────────────
            int64_t Bk_inv_c = static_cast<int64_t>(Bk_inv.ConvertToInt<uint64_t>());
            if (Bk_inv_c > static_cast<int64_t>(t / 2))
                Bk_inv_c -= static_cast<int64_t>(t);
            // NTT of a constant scalar is that scalar repeated in every slot
            auto pt_one = cc->MakePackedPlaintext(
                std::vector<int64_t>(ring_dim, Bk_inv_c));
            result[k + ell] = cc->Encrypt(keys.publicKey, pt_one);
        }

        return result;
    }
}

int main() {
    
    return 0;
}