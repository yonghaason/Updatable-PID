#include "SSLJ.h"
#include "secure-join/Perm/AltModPerm.h"
#include "secure-join/Perm/PermCorrelation.h"

using namespace std;
using namespace oc;
using namespace secJoin;
using namespace volePSI;

namespace uppid 
{
    // inline oc::block rowAsBlock(oc::MatrixView<const oc::u8> M, oc::u64 i)
    // {
    //     if (M.cols() != 16) throw RTE_LOC;
    //     if (i >= M.rows())  throw RTE_LOC;

    //     oc::block out;
    //     std::memcpy(&out, M.data(i), 16);
    //     return out;
    // }

    Proto SsljSender::send(
        oc::span<oc::block> Y,
        oc::MatrixView<oc::u8> datas,
        oc::BitVector& memShares,
        oc::Matrix<oc::u8>& valueShares,
        Socket& chl)
    {
        u64 receiverSize;
        co_await chl.send(Y.size());
        co_await chl.recv(receiverSize);

        volePSI::RsCpsiSender cpsiSender;
        cpsiSender.init(Y.size(), receiverSize, mDataByteSize, 40, mPrng.get(), 1, ValueShareType::Xor);
        RsCpsiSender::Sharing cpsiResults;
        co_await cpsiSender.send(Y, datas, cpsiResults, chl);

        u64 cpsiSize = cpsiResults.mFlagBits.size();

        secJoin::PermCorReceiver permCorReceiver;
        secJoin::AltModPermGenReceiver permGenReceiver;

        secJoin::CorGenerator ole;
        ole.init(chl.fork(), mPrng, 0, 1, mOteBatchSize, false);
        permGenReceiver.init(cpsiSize, mDataByteSize+1, ole);

        co_await macoro::when_all_ready(
            ole.start(),
            permGenReceiver.generate(mPrng, chl, permCorReceiver)
        );

        valueShares.resize(cpsiSize, mDataByteSize, oc::AllocType::Uninitialized);

        co_await permCorReceiver.apply<u8>(
            PermOp::Regular, cpsiResults.mValues, valueShares, chl);

        oc::Matrix<oc::u8> memSharesU8(cpsiSize, 1, oc::AllocType::Uninitialized);
        for (oc::u64 i = 0; i < cpsiSize; ++i) {
            memSharesU8(i, 0) = static_cast<oc::u8>(cpsiResults.mFlagBits[i]);
        }

        oc::Matrix<oc::u8> memSharesU8Aligned(
            cpsiSize, 1, oc::AllocType::Uninitialized);
        co_await permCorReceiver.apply<oc::u8>(
            PermOp::Regular, memSharesU8, memSharesU8Aligned, chl);

        memShares.resize(cpsiSize);
        for (oc::u64 i = 0; i < cpsiSize; ++i) {
            memShares[i] = (memSharesU8Aligned(i, 0) & 1);
        }

        memShares.resize(receiverSize);
        valueShares.resize(receiverSize, mDataByteSize);

    };

    Proto SsljReceiver::recv(
        oc::span<oc::block> X,
        oc::BitVector& memShares,
        oc::Matrix<oc::u8>& valueShares,
        Socket& chl)
    {
        oc::u64 senderSize;
        co_await chl.recv(senderSize);
        co_await chl.send(X.size());

        volePSI::RsCpsiReceiver cpsiReceiver;
        cpsiReceiver.init(senderSize, X.size(), mDataByteSize, 40, mPrng.get(), 1, ValueShareType::Xor);
        RsCpsiReceiver::Sharing cpsiResults;
        co_await cpsiReceiver.receive(X, cpsiResults, chl);

        u64 cpsiSize = cpsiResults.mFlagBits.size();

        std::vector<oc::u32> inputToShareIdx(cpsiSize);
        std::vector<uint8_t> used(cpsiSize, 0);
        for (size_t i = 0; i < X.size(); i++) {
            inputToShareIdx[i] = cpsiResults.mMapping[i];
            used[inputToShareIdx[i]] = 1;
        }

        size_t out = X.size();
        for (oc::u32 i = 0; i < cpsiSize; ++i) {
            if (!used[i]) {
                inputToShareIdx[out++] = i;
                if (out == cpsiSize) break;
            }
        }
            
        secJoin::Perm perm(inputToShareIdx);

        secJoin::PermCorSender permCorSender;
        secJoin::AltModPermGenSender permGenSender;

        secJoin::CorGenerator ole;
        ole.init(chl.fork(), mPrng, 1, 1, mOteBatchSize, false);
        permGenSender.init(cpsiSize, mDataByteSize+1, ole);

        co_await macoro::when_all_ready(
            ole.start(),
            permGenSender.generate(perm, mPrng, chl, permCorSender)
        );

        valueShares.resize(cpsiSize, mDataByteSize, oc::AllocType::Uninitialized);

        co_await permCorSender.apply<u8>(
            PermOp::Regular, cpsiResults.mValues, valueShares, chl);

        oc::Matrix<oc::u8> memSharesU8(cpsiSize, 1, oc::AllocType::Uninitialized);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memSharesU8(i, 0) = static_cast<oc::u8>(cpsiResults.mFlagBits[i]);

        oc::Matrix<oc::u8> memSharesU8Aligned(
            cpsiSize, 1, oc::AllocType::Uninitialized);
        co_await permCorSender.apply<oc::u8>(
            PermOp::Regular, memSharesU8, memSharesU8Aligned, chl);

        memShares.resize(cpsiSize);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memShares[i] = (memSharesU8Aligned(i, 0) & 1);

        memShares.resize(X.size());
        valueShares.resize(X.size(), mDataByteSize);
    }
}