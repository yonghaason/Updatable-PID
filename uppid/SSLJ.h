#pragma once
#include "volePSI/RsCpsi.h"

namespace uppid
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    struct SsljBase
    {
        oc::u64 mOteBatchSize;
        oc::PRNG mPrng;
        oc::u64 mDataByteSize;

        void init(
            oc::u64 dataByteSize,
            oc::block seed = oc::ZeroBlock,
            oc::u64 oteBatchSize  = 1ull << 22)
        {
            mDataByteSize = dataByteSize;
            mPrng.SetSeed(seed);
            mOteBatchSize = oteBatchSize;
        }
        
    };
    
    class SsljSender : public SsljBase, oc::TimerAdapter
    {
    public:
        Proto send(
            oc::span<oc::block> Y,
            oc::MatrixView<oc::u8> datas,
            oc::BitVector& memShares,
            oc::Matrix<oc::u8>& sharings,
            Socket& chl);
    };

    class SsljReceiver : public SsljBase, oc::TimerAdapter
    {
    public:
        Proto recv(
            oc::span<oc::block> X,
            oc::BitVector& memShares,
            oc::Matrix<oc::u8>& sharings,
            Socket& chl);
    };

}