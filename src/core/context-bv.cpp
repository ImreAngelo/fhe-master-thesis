#include "context-bv.h"

using namespace Context;

RGSW BV::EncryptRGSW(const PublicKey<DCRTPoly> &, const Plaintext &, const bool noiseless) const
{
    const auto msg = plaintext->GetElement<DCRTPoly>();

}

RLWE BVContext::EvalExternalProduct(const RLWE &, const RGSW &) const
{
    return RLWE();
}

RGSW BVContext::EvalInternalProduct(const RGSW &, const RGSW &) const
{
    return RGSW();
}

std::vector<DCRTPoly> BVContext::PowersOfBase(const DCRTPoly &input) const
{
    return std::vector<DCRTPoly>();
}

std::vector<DCRTPoly> BVContext::Decompose(const DCRTPoly &input) const
{
    return std::vector<DCRTPoly>();
}
