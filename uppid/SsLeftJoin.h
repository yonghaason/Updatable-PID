#pragma once
#include "volePSI/RsCpsi.h"

namespace uppid
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    struct SsLeftJoinBase
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
    
    class SsLeftJoinSender : public SsLeftJoinBase, oc::TimerAdapter
    {
    public:
        /**
         * input: Y, datas
         * output: memShares, sharings
         * - memShares[i]   = (x[i] in Y)
         * - sharings[i]    = if x[i] in Y, Boolean shares of datas[x[i]]
         * 
         * Caution: No guarantee for sharings[i] when x[i] notin Y
         * In particular, NOT a share of zero
         */
        Proto send(
            oc::span<oc::block> Y,
            oc::MatrixView<oc::u8> datas,
            oc::BitVector& memShares,
            oc::Matrix<oc::u8>& sharings,
            Socket& chl);
    };

    class SsLeftJoinReceiver : public SsLeftJoinBase, oc::TimerAdapter
    {
    public:
        /**
         * input: X = [x[i]]
         * output: memShares, sharings
         * - memShares[i]   = (x[i] in Y)
         * - sharings[i]    = if x[i] in Y, Boolean shares of datas[x[i]]
         * 
         * Caution: No guarantee for sharings[i] when x[i] notin Y
         * In particular, NOT a share of zero
         */
        Proto recv(
            oc::span<oc::block> X,
            oc::BitVector& memShares,
            oc::Matrix<oc::u8>& sharings,
            Socket& chl);
    };

}