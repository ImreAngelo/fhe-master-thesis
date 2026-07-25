#include "client/encrypt.h"

namespace spar::client {

using core::CryptoContext;
using core::ExtendedContext;
using core::PrivateKey;
using core::RGSW;
using core::RLWE;

std::vector<RLWE> Decrypt(const CryptoContext& cc, const std::vector<RLWE>& cts, const PrivateKey& secret, const bool is_lead) {
    return (is_lead) ? cc->MultipartyDecryptLead(cts, secret) : cc->MultipartyDecryptMain(cts, secret);
}

}  // namespace spar::client
