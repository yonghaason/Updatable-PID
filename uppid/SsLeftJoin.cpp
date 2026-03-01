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
            // simple mixing
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

        // Invoke CPSI
        volePSI::RsCpsiSender cpsiSender;
        cpsiSender.init(Y.size(), receiverSize, mDataByteSize, 40, mPrng.get(), 1, ValueShareType::Xor);
        RsCpsiSender::Sharing cpsiResults;
        co_await cpsiSender.send(Y, datas, cpsiResults, chl);

        if (debugCorrectness) {
            // (1) Send the sender's CPSI flag shares (length = cpsiSize).
            co_await chl.send(cpsiResults.mFlagBits);

            // (2) Send Y in plaintext so the receiver can compute ground-truth membership (debug only).
            std::vector<oc::block> yPlain(Y.begin(), Y.end());
            co_await chl.send(yPlain);
        }

        u64 cpsiSize = cpsiResults.mFlagBits.size();

        secJoin::PermCorReceiver permCorReceiver;
        secJoin::AltModPermGenReceiver permGenReceiver;

        secJoin::CorGenerator ole;
        ole.init(chl.fork(), mPrng, 0, 1, mOteBatchSize, false);
        permGenReceiver.init(cpsiSize, mDataByteSize+1, ole);

        // generate correlated randoms value required for P&S
        co_await macoro::when_all_ready(
            ole.start(),
            permGenReceiver.generate(mPrng, chl, permCorReceiver)
        );

        valueShares.resize(cpsiSize, mDataByteSize, oc::AllocType::Uninitialized);

        // invoke P&S with payload
        co_await permCorReceiver.apply<u8>(
            PermOp::Regular, cpsiResults.mValues, valueShares, chl);

        oc::Matrix<oc::u8> memSharesU8(cpsiSize, 1, oc::AllocType::Uninitialized);
        for (oc::u64 i = 0; i < cpsiSize; ++i) {
            memSharesU8(i, 0) = static_cast<oc::u8>(cpsiResults.mFlagBits[i]);
        }

        oc::Matrix<oc::u8> memSharesU8Aligned(
            cpsiSize, 1, oc::AllocType::Uninitialized);
        // invoke P&S with membership bit
        co_await permCorReceiver.apply<oc::u8>(
            PermOp::Regular, memSharesU8, memSharesU8Aligned, chl);

        memShares.resize(cpsiSize);
        for (oc::u64 i = 0; i < cpsiSize; ++i) {
            memShares[i] = (memSharesU8Aligned(i, 0) & 1);
        }

        // Compact the tables by dropping the dummy rows and keeping only the |X| meaningful rows.
        memShares.resize(receiverSize);
        valueShares.resize(receiverSize, mDataByteSize);

        if (debugCorrectness) {
            // After P&S (alignment/resize completed), send the sender's memShares to the receiver.
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

        oc::u64 senderSize;
        co_await chl.recv(senderSize);
        co_await chl.send(X.size());

        // Invoke CPSI
        volePSI::RsCpsiReceiver cpsiReceiver;
        cpsiReceiver.init(senderSize, X.size(), mDataByteSize, 40, mPrng.get(), 1, ValueShareType::Xor);
        RsCpsiReceiver::Sharing cpsiResults;
        co_await cpsiReceiver.receive(X, cpsiResults, chl);

        // debug
        u64 cpsiSize = cpsiResults.mFlagBits.size();
        oc::BitVector openedAfterCpsi;
        
        std::unordered_set<oc::block, BlockHash, BlockEq> ySet;
        if (debugCorrectness) {
        
            oc::BitVector senderFlagShare;
            senderFlagShare.resize(cpsiResults.mFlagBits.size());
            co_await chl.recv(senderFlagShare);

            if (senderFlagShare.size() != cpsiSize) {
                std::cout << "\n\n[DEBUG][CPSI] size mismatch: senderFlagShare.size()="
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
                u64 idx = cpsiResults.mMapping[i];          
                bool opened = (senderFlagShare[idx] ^ cpsiResults.mFlagBits[idx]); 
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

        //make permutation pi
        std::vector<oc::u32> inputToShareIdx(cpsiSize);
        std::vector<uint8_t> used(cpsiSize, 0);

        // CPSI make injective function, idx: X -> |M|, idx(x) -> i (secret share table index)
        // we want to permutation pi operated, pi(idx(x_i)) = i
        // we store idx(x_i) for each i and mark which CPSI table indices are used.
        for (size_t i = 0; i < X.size(); i++) {
            inputToShareIdx[i] = cpsiResults.mMapping[i];
            used[inputToShareIdx[i]] = 1;
        }

        // Place unused indices in the positions beyond |X|.
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

        // generate correlated randoms value required for P&S
        co_await macoro::when_all_ready(
            ole.start(),
            permGenSender.generate(perm, mPrng, chl, permCorSender)
        );

        valueShares.resize(cpsiSize, mDataByteSize, oc::AllocType::Uninitialized);

        // invoke P&S with payload
        co_await permCorSender.apply<u8>(
            PermOp::Regular, cpsiResults.mValues, valueShares, chl);

        oc::Matrix<oc::u8> memSharesU8(cpsiSize, 1, oc::AllocType::Uninitialized);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memSharesU8(i, 0) = static_cast<oc::u8>(cpsiResults.mFlagBits[i]);

        oc::Matrix<oc::u8> memSharesU8Aligned(
            cpsiSize, 1, oc::AllocType::Uninitialized);
        // invoke P&S with membership bit
        co_await permCorSender.apply<oc::u8>(
            PermOp::Regular, memSharesU8, memSharesU8Aligned, chl);

        memShares.resize(cpsiSize);
        for (oc::u64 i = 0; i < cpsiSize; ++i)
            memShares[i] = (memSharesU8Aligned(i, 0) & 1);

        // Compact the tables by dropping the dummy rows and keeping only the |X| meaningful rows.
        memShares.resize(X.size());
        valueShares.resize(X.size(), mDataByteSize);
        
        // debug
        if (debugCorrectness) {
            // std::cout << "P&S Debug start X.size is " << X.size() << " \n";
            // Receive the sender's memShares after P&S reordering.
            oc::BitVector senderAlignedShare;
            senderAlignedShare.resize(X.size());
            co_await chl.recv(senderAlignedShare);
            // std::cout << "Receiver Sender membership bit\n";

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

                // (Extra) If the opened value right after CPSI differs from the value after P&S,
                //         the issue is likely in P&S (permutation/correlation).
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

    }
}