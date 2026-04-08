namespace core {
    template <typename T>
    using RGSWCiphertext = std::vector<lbcrypto::Ciphertext<T>>;


    template <typename T>
    RGSWCiphertext<T> expandRlwe()
    {
        return RGSWCiphertext<T>();    
    }
}