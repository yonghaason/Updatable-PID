#include "SsLeftJoin.h"
#include "secure-join/Perm/AltModPerm.h"
#include "secure-join/Perm/PermCorrelation.h"

using namespace std;
using namespace oc;
using namespace secJoin;
using namespace volePSI;

namespace uppid 
{

    const bool debugCorrectness = false;
    

    struct BlockHash {
        size_t operator()(const oc::block& b) const noexcept {
            uint64_t w[2];
            std::memcpy(w, &b, sizeof(b));
            // 간단한 mixing
            uint64_t x = w[0] ^ (w[1] + 0x9e3779b97f4a7c15ULL + (w[0] << 6) + (w[0] >> 2));
            return static_cast<size_t>(x);
        }
    };
    struct BlockEq {
        bool operator()(const oc::block& a, const oc::block& b) const noexcept {
            return std::memcmp(&a, &b, sizeof(oc::block)) == 0;
        }
    };
    

    Proto SsLeftJoinSender::send(
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

        if (debugCorrectness) {
            // (1) Sender의 CPSI flag share 전송 (길이 = cpsiSize)
            co_await chl.send(cpsiResults.mFlagBits);

            // (2) Receiver가 ground-truth membership을 계산할 수 있도록 Y 평문 전송 (디버그 전용)
            std::vector<oc::block> yPlain(Y.begin(), Y.end());
            co_await chl.send(yPlain);
        }

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

        if (debugCorrectness) {
            // P&S 이후(정렬/resize 완료된) sender의 memShares share를 receiver에게 전송
            std::cout << "sender sended data size is " << memShares.size() << '\n';
            co_await chl.send(memShares);
        }

    };

    Proto SsLeftJoinReceiver::recv(
        oc::span<oc::block> X,
        oc::BitVector& memShares,
        oc::Matrix<oc::u8>& valueShares,
        Socket& chl)
    {
        Timer timer;
        timer.setTimePoint("start");

        int debug = 1;

        oc::u64 senderSize;
        co_await chl.recv(senderSize);
        co_await chl.send(X.size());
        
        // std::cout << "senderSize is " << senderSize << " X.size() is " << X.size() << "\n";

        volePSI::RsCpsiReceiver cpsiReceiver;
        cpsiReceiver.init(senderSize, X.size(), mDataByteSize, 40, mPrng.get(), 1, ValueShareType::Xor);
        RsCpsiReceiver::Sharing cpsiResults;
        co_await cpsiReceiver.receive(X, cpsiResults, chl);

        // std::cout << "CPSI, cpsiSize is " << cpsiResults.mFlagBits.size() << '\n';
        timer.setTimePoint("CPSI");

        u64 cpsiSize = cpsiResults.mFlagBits.size();
        oc::BitVector openedAfterCpsi;
        // correctness check

        std::unordered_set<oc::block, BlockHash, BlockEq> ySet;
        if (debugCorrectness) {
        
            oc::BitVector senderFlagShare;
            senderFlagShare.resize(cpsiResults.mFlagBits.size());
            co_await chl.recv(senderFlagShare);

            if (senderFlagShare.size() != cpsiSize) {
                std::cout << "[DEBUG][CPSI] size mismatch: senderFlagShare.size()="
                        << senderFlagShare.size() << " cpsiSize=" << cpsiSize << "\n";
            }

            // Sender set
            std::vector<oc::block> yPlain(senderSize);
            co_await chl.recv(yPlain);
            
            // ySet.reserve(static_cast<size_t>(yPlain.size() * 1.3) + 1);
            ySet.reserve(yPlain.size());
            for (auto& b : yPlain) ySet.insert(b);

            openedAfterCpsi.resize(X.size());

            size_t mism = 0;
            for (u64 i = 0; i < X.size(); ++i) {
                u64 idx = cpsiResults.mMapping[i];          // X[i]가 매핑된 CPSI output index
                bool opened = (senderFlagShare[idx] ^ cpsiResults.mFlagBits[idx]); // 실제 membership bit
                bool expected = (ySet.find(X[i]) != ySet.end());

                openedAfterCpsi[i] = opened;

                if (opened != expected) {
                    if (mism < 10) {
                        std::cout << "[DEBUG][CPSI mismatch] i=" << i
                                << " mapIdx=" << idx
                                << " opened=" << opened
                                << " expected=" << expected << "\n";
                    }
                    ++mism;
                }
            }
            std::cout << "[DEBUG] After CPSI: mismatches=" << mism << "/" << X.size() << "\n";

        }

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

        timer.setTimePoint("make Permutation");
            
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

        // std::cout << "generate random value, Batch size is " << mOteBatchSize << "\n";
        timer.setTimePoint("generate random value by P&S");

        valueShares.resize(cpsiSize, mDataByteSize, oc::AllocType::Uninitialized);

        co_await permCorSender.apply<u8>(
            PermOp::Regular, cpsiResults.mValues, valueShares, chl);

        // std::cout << "P&S with value \n";
        timer.setTimePoint("P&S with value");

        oc::Matrix<oc::u8> memSharesU8(cpsiSize, 1, oc::AllocType::Uninitialized);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memSharesU8(i, 0) = static_cast<oc::u8>(cpsiResults.mFlagBits[i]);

        oc::Matrix<oc::u8> memSharesU8Aligned(
            cpsiSize, 1, oc::AllocType::Uninitialized);
        co_await permCorSender.apply<oc::u8>(
            PermOp::Regular, memSharesU8, memSharesU8Aligned, chl);

        // std::cout << "P&S with flags \n";
        timer.setTimePoint("P&S with flags");

        memShares.resize(cpsiSize);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memShares[i] = (memSharesU8Aligned(i, 0) & 1);

        memShares.resize(X.size());
        valueShares.resize(X.size(), mDataByteSize);
        
        if (debugCorrectness) {
            std::cout << "P&S Debug start X.size is " << X.size() << " \n";
            // Sender의 "P&S 이후 정렬된 memShares share" 수신
            oc::BitVector senderAlignedShare;
            senderAlignedShare.resize(X.size());
            co_await chl.recv(senderAlignedShare);
            std::cout << "Receiver Sender membership bit\n";

            if (senderAlignedShare.size() != X.size() || memShares.size() != X.size()) {
                std::cout << "[DEBUG][P&S] size mismatch: senderAlignedShare.size()="
                        << senderAlignedShare.size()
                        << " memShares.size()=" << memShares.size()
                        << " X.size()=" << X.size() << "\n";
            }

            size_t mismPS = 0;
            size_t mismPSvsCpsi = 0;

            for (u64 i = 0; i < X.size(); ++i) {
                bool openedPS = (senderAlignedShare[i] ^ memShares[i]);
                bool expected = (ySet.find(X[i]) != ySet.end());

                if (openedPS != expected) {
                    if (mismPS < 10) {
                        std::cout << "[DEBUG][P&S mismatch] i=" << i
                                << " openedPS=" << openedPS
                                << " expected=" << expected << "\n";
                    }
                    ++mismPS;
                }

                // (추가) CPSI 직후에 열어둔 값과 P&S 직후 값이 달라지면 -> P&S(permutation/correlation) 쪽 문제
                if (openedAfterCpsi.size() == X.size() && openedPS != openedAfterCpsi[i]) {
                    if (mismPSvsCpsi < 10) {
                        std::cout << "[DEBUG][P&S != CPSI-opened] i=" << i
                                << " openedCpsi=" << (bool)openedAfterCpsi[i]
                                << " openedPS=" << openedPS << "\n";
                    }
                    ++mismPSvsCpsi;
                }
            }

            std::cout << "[DEBUG] After P&S: mismatches=" << mismPS << "/" << X.size() << "\n";
            std::cout << "[DEBUG] P&S vs CPSI-opened diff count=" << mismPSvsCpsi << "/" << X.size() << "\n";
        }

        // std::cout << timer << '\n';
    }
}