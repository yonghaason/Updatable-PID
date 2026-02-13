#pragma once
#include "secure-join/Prf/AltModPrfProto.h"

namespace uppid
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    enum class PrfType
    {
        DDH = 1,
        AltMod = 2
    };
    
    class DoublePrf : public oc::TimerAdapter
    {
        PrfType mPrfType;
        oc::PRNG mPrng;

        // For AltMod
        oc::u64 mOteBatch;
        secJoin::AltModPrf::KeyType mAmKey;

        // For DDH
        struct DdhImpl;
        std::unique_ptr<DdhImpl> mDdh;

    public:

        DoublePrf();
        ~DoublePrf();

        DoublePrf(DoublePrf&&) noexcept;
        DoublePrf& operator=(DoublePrf&&) noexcept;

        DoublePrf(const DoublePrf&) = delete;
        DoublePrf& operator=(const DoublePrf&) = delete;

        void init(
            PrfType prfType = PrfType::AltMod, 
            oc::block seed = oc::ZeroBlock,
            oc::u64 oteBatch = 1ull << 22);

        Proto recv(
            oc::span<oc::block> input, 
            std::vector<oc::block>& UID, 
            Socket& chl);

        Proto send(Socket& chl);

        // Proto recvDDH(
        //     oc::span<oc::block> input, 
        //     std::vector<oc::block>& UID, 
        //     Socket& chl);

        // Proto sendDDH(Socket& chl);
    };
}