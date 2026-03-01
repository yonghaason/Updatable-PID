#include "PseudonymisedDB.h"
#include <cstring> // memcpy

using namespace std;
using namespace oc;
using namespace secJoin;


namespace uppid
{
    // PseudonymisedDB::ssMuxRecv(
    //     oc::BitVector& memShare,
    //     oc::MatrixView<oc::u8>& dataShare,
    // )
    // {
    //     oc::SilentOtExtReceiver otReceiver;
    //     otReceiver.configure(memShare.size());

    // }

    // helper: row-major Matrix<u8> <-> vector<block>

    static inline void packToBlocks(
        const oc::Matrix<oc::u8>& M,
        oc::u64 rows,
        oc::u64 colsBytes,
        std::vector<oc::block>& out)
    {
        const oc::u64 numBlk = (colsBytes + 15) / 16;
        out.resize(rows * numBlk);

        for (oc::u64 i = 0; i < rows; ++i)
        {
            const oc::u8* rowPtr = M.data(i);
            for (oc::u64 j = 0; j < numBlk; ++j)
            {
                alignas(16) oc::u8 buf[16] = {};
                const oc::u64 off = j * 16;
                const oc::u64 len = std::min<oc::u64>(16, colsBytes > off ? (colsBytes - off) : 0);
                if (len) std::memcpy(buf, rowPtr + off, len);

                oc::block b;
                std::memcpy(&b, buf, 16);
                out[i * numBlk + j] = b;
            }
        }
    }

    static inline void unpackFromBlocks(
        const std::vector<oc::block>& in,
        oc::u64 rows,
        oc::u64 colsBytes,
        oc::Matrix<oc::u8>& M)
    {
        const oc::u64 numBlk = (colsBytes + 15) / 16;

        for (oc::u64 i = 0; i < rows; ++i)
        {
            oc::u8* rowPtr = M.data(i);
            for (oc::u64 j = 0; j < numBlk; ++j)
            {
                alignas(16) oc::u8 buf[16];
                std::memcpy(buf, &in[i * numBlk + j], 16);

                const oc::u64 off = j * 16;
                const oc::u64 len = std::min<oc::u64>(16, colsBytes > off ? (colsBytes - off) : 0);
                if (len) std::memcpy(rowPtr + off, buf, len);
            }
        }
    }



    // P_0 by set X
    PseudonymisedDB_P0::PseudonymisedDB_P0(        
        oc::u64 dataByteSize,
        oc::block randomSeed,
        PrfType prfType,
        oc::u64 oteBatchSize)
    {
        mDoublePrf.init(prfType, randomSeed, oteBatchSize);
        mSsljReceiver.init(dataByteSize, randomSeed, oteBatchSize);
        mSsljSender.init(dataByteSize, randomSeed, oteBatchSize);

        myData.resize(0, dataByteSize);
        dataShare.resize(0, dataByteSize);

        if (dataByteSize != 16)
            throw RTE_LOC;

        
    };

    Proto PseudonymisedDB_P0::insertID(
        oc::span<oc::block> input, 
        // oc::MatrixView<oc::u8> inputData,
        Socket& chl)
    {
        std::vector<oc::block> updatedUID;
        
        co_await mDoublePrf.recv(input, updatedUID, chl);

        UID.reserve(UID.size() + updatedUID.size());
        UID.insert(UID.end(), 
            std::make_move_iterator(updatedUID.begin()),
            std::make_move_iterator(updatedUID.end()));
        // myData.resize(UID.size(), myData.cols(), oc::AllocType::Uninitialized);
        // std::memcpy(
        //     myData.data(myData.rows()), inputData.data(), inputData.size());
    };

    void PseudonymisedDB_P0::DinsertID(
        oc::span<oc::block> input
    )
    {
        UID.reserve(UID.size() + input.size());
        UID.insert(UID.end(), 
            std::make_move_iterator(input.begin()),
            std::make_move_iterator(input.end()));

    };

    Proto PseudonymisedDB_P0::respondOPRF(
        Socket& chl)
    {
        co_await mDoublePrf.send(chl);
        co_return;
    };

    Proto PseudonymisedDB_P0::shareUpdate_P0(Socket& chl)
    {
        
        // SSLJ Receiver is P_0 (permutation)

        PRNG prng;
        prng.SetSeed(oc::OneBlock);

        auto currentSize = memShare.size();
        auto updatedSize = UID.size() - currentSize;
        
        oc::span<oc::block> previousIDs(UID.data(), currentSize);               // X
        oc::span<oc::block> updatedIDs(UID.data() + currentSize, updatedSize);  // X'

        co_await chl.send(previousIDs.size());
        co_await chl.send(updatedIDs.size());

        oc::BitVector memShare4PrevIDs;
        oc::Matrix<oc::u8> dataShare4PrevIDs;

        if (currentSize != 0){ // if previous set is empty, skip
            co_await mSsljReceiver.recv(
                previousIDs, memShare4PrevIDs, dataShare4PrevIDs, chl);             // SSLJ (X, Y'), provide X

            // Below computation (simple XOR) is correct only when Y ∩ Y' is empty.
            // To support Y ∩ Y' nonempty case, 
            // need to compute memShare OR memShare4PrevIDs.
            memShare ^= memShare4PrevIDs;                                            // T xor T^new

            // naive secret share of CPSI are not zero-sharing
            // The following code constructs a simple OT-based GMW protocol to make that the share is zero.
            const u64 rows = memShare4PrevIDs.size();
            const u64 cols = 16;
            const u64 numBlk = (cols + 15) / 16;
            const u64 otCount = rows * numBlk;

            std::vector<block> a0;
            // matrix(u8) convert to block, we assume that item length is 128bit
            packToBlocks(dataShare4PrevIDs, rows, cols, a0);

            // ---------- OT#1: P1(sender) -> P0(receiver), choice = m0
            oc::BitVector choice_m0(otCount);
            for (u64 i = 0; i < rows; ++i) {
                const bool m0 = memShare4PrevIDs[i];
                for (u64 j = 0; j < numBlk; ++j) {
                    choice_m0[i * numBlk + j] = m0;
                }
            }

            std::vector<block> t01(otCount); // receive M_{m0}
            oc::SilentOtExtReceiver ot1Receiver;
            ot1Receiver.configure(otCount);
            co_await ot1Receiver.receiveChosen(choice_m0, t01, prng, chl);

            // ---------- OT#2: P0(sender) -> P1(receiver), messages: N0=r10, N1=r10 ^ a0
            std::vector<block> r10(otCount);
            prng.get(r10.data(), otCount);

            std::vector<std::array<block,2>> ot2Msgs(otCount);
            for (u64 k = 0; k < otCount; ++k) {
                ot2Msgs[k][0] = r10[k];
                ot2Msgs[k][1] = r10[k] ^ a0[k];
            }

            oc::SilentOtExtSender ot2Sender;
            ot2Sender.configure(otCount);
            co_await ot2Sender.sendChosen(ot2Msgs, prng, chl);

            // ---------- local term: l0 = m0 ? a0 : 0
            for (u64 i = 0; i < rows; ++i) {
                if (!memShare4PrevIDs[i]) {
                    for (u64 j = 0; j < numBlk; ++j) {
                        a0[i * numBlk + j] = oc::ZeroBlock;
                    }
                }
            }

            // ---------- P0 final masked share:
            // q0 = l0 ^ t01 ^ r10
            for (u64 k = 0; k < otCount; ++k) {
                a0[k] = a0[k] ^ t01[k] ^ r10[k];
            }

            // block -> matrix(u8)
            unpackFromBlocks(a0, rows, cols, dataShare4PrevIDs);


        }
        
        oc::BitVector memShare4Upd;
        oc::Matrix<oc::u8> dataShare4Upd;
        co_await mSsljReceiver.recv(
            updatedIDs, memShare4Upd, dataShare4Upd, chl);                        // SSLJ (X', Y \cup Y'), provide X'

        // T || T^add
        memShare.append(memShare4Upd);                                            
        dataShare.resize(UID.size(), dataShare.cols(), AllocType::Uninitialized);
        std::memcpy(
            dataShare.data(currentSize), dataShare4Upd.data(), dataShare4Upd.size());
        
    }




    // P_1 by set Y along with associated payload p_y
        PseudonymisedDB_P1::PseudonymisedDB_P1(        
        oc::u64 dataByteSize,
        oc::block randomSeed,
        PrfType prfType,
        oc::u64 oteBatchSize)
    {
        mDoublePrf.init(prfType, randomSeed, oteBatchSize);
        mSsljReceiver.init(dataByteSize, randomSeed, oteBatchSize);
        mSsljSender.init(dataByteSize, randomSeed, oteBatchSize);
        myData.resize(0, dataByteSize);
        dataShare.resize(0, dataByteSize);

        YSize = 0;

        if (dataByteSize != 16)
            throw RTE_LOC;
    };

    Proto PseudonymisedDB_P1::insertID(
        oc::span<oc::block> input, 
        oc::MatrixView<oc::u8> inputData,
        Socket& chl)
    {
        std::vector<oc::block> updatedUID;
        co_await mDoublePrf.recv(input, updatedUID, chl);

        size_t oldRows = myData.rows();

        UID.reserve(UID.size() + updatedUID.size());
        UID.insert(UID.end(), 
            std::make_move_iterator(updatedUID.begin()),
            std::make_move_iterator(updatedUID.end()));
        myData.resize(UID.size(), myData.cols(), oc::AllocType::Uninitialized);
        std::memcpy(
            myData.data(oldRows), inputData.data(), inputData.size());
    };

    void PseudonymisedDB_P1::DinsertID(
        oc::span<oc::block> input,
        oc::MatrixView<oc::u8> inputData
    )
    {
        UID.reserve(UID.size() + input.size());
        UID.insert(UID.end(), 
            std::make_move_iterator(input.begin()),
            std::make_move_iterator(input.end()));
        
        size_t oldRows = myData.rows();
        myData.resize(UID.size(), myData.cols(), oc::AllocType::Uninitialized);
        std::memcpy(
            myData.data(oldRows), inputData.data(), inputData.size());

    };

    Proto PseudonymisedDB_P1::respondOPRF(
        Socket& chl)
    {
        co_await mDoublePrf.send(chl);
        co_return;
    };

    Proto PseudonymisedDB_P1::shareUpdate_P1(Socket& chl)
    {

        // SSLJ Sender is P_1 (Y, payload)
        oc::Timer timer;
        PRNG prng;
        prng.SetSeed(oc::ZeroBlock);

        u64 XSize;
        u64 X_Size; // X' size
        
        co_await chl.recv(XSize); // pervious X size
        co_await chl.recv(X_Size); // new X' size

        // auto currentSize = memShare.size();
        auto currentSize = YSize;
        auto updatedSize = UID.size() - currentSize;
        
        YSize = UID.size();

        oc::span<oc::block> updatedIDs(UID.data() + currentSize, updatedSize);  // Y'
        oc::span<oc::block> AllIDs(UID.data(), UID.size());                     // Y \cup Y'

        u64 cols = myData.cols();
        oc::MatrixView<oc::u8> updatedPayloads(                                 // Y'           payload
            myData.data() + currentSize * cols,  // row offset
            updatedSize,                        // number of rows
            cols                                // number of columns
        );
        
        oc::MatrixView<oc::u8> AllPayloads(                                     // Y \cup Y'    payload
            myData.data(),      
            UID.size(),         
            cols
        );

        oc::BitVector memShare4PrevIDs;
        oc::Matrix<oc::u8> dataShare4PrevIDs;
        
        timer.setTimePoint("start");
        if (currentSize != 0) // if previous set is empty, skip
        {
            co_await mSsljSender.send(                                              // SSLJ (X, Y'), provide Y' with payload
                updatedIDs, updatedPayloads, memShare4PrevIDs, dataShare4PrevIDs, chl);

            // Below computation (simple XOR) is correct only when Y ∩ Y' is empty.
            // To support Y ∩ Y' nonempty case, 
            // need to compute memShare OR memShare4PrevIDs.
            memShare ^= memShare4PrevIDs;                                           // T xor T^new

            // naive secret share of CPSI are not zero-sharing
            // The following code constructs a simple OT-based GMW protocol to make that the share is zero.
            const u64 rows = memShare4PrevIDs.size();          
            const u64 cols = 16;                    // payload bytes (== dataByteSize)
            const u64 numBlk = (cols + 15) / 16;
            const u64 otCount = rows * numBlk;

            // matrix(u8) convert to block, we assume that item length is 128bit
            std::vector<block> a1;
            packToBlocks(dataShare4PrevIDs, rows, cols, a1);
            
            // ---------- OT#1: P1(sender) -> P0(receiver) , messages: N0=r10, N1=r10 ^ a0
            std::vector<block> r01(otCount);
            prng.get(r01.data(), otCount);

            std::vector<std::array<block, 2>> ot1Msgs(otCount);

            for (u64 k = 0; k < otCount; k++) {
                ot1Msgs[k][0] = r01[k];
                ot1Msgs[k][1] = r01[k] ^ a1[k];
            }

            oc::SilentOtExtSender ot1Sender;
            ot1Sender.configure(otCount);

            co_await ot1Sender.sendChosen(ot1Msgs, prng, chl);

            // ---------- OT#2: P0(sender) -> P1(receiver), , choice = m1

            oc::BitVector choice_m1(otCount);
            for (u64 i = 0; i < rows; ++i) {
                const bool m1 = memShare4PrevIDs[i];
                for (u64 j = 0; j < numBlk; ++j) {
                    choice_m1[i * numBlk + j] = m1;
                }
            }

            std::vector<block> t10(otCount); // receive N_{m1}
            oc::SilentOtExtReceiver ot2Receiver;
            ot2Receiver.configure(otCount);
            co_await ot2Receiver.receiveChosen(choice_m1, t10, prng, chl);

            // ---------- local term: l1 = m1 ? a1 : 0  (m1 is P1 share bit)
            for (u64 i = 0; i < rows; ++i) {
                if (!memShare4PrevIDs[i]) {
                    for (u64 j = 0; j < numBlk; ++j) {
                        a1[i * numBlk + j] = oc::ZeroBlock;
                    }
                }
            }

            // ---------- P1 final masked share:
            // q1 = l1 ^ r01 ^ t10  ==> XOR with P0's q0 yields m * payload; 0 if non-member
            for (u64 k = 0; k < otCount; ++k) {
                a1[k] = a1[k] ^ r01[k] ^ t10[k];
            }

            // block -> matrix(u8)
            unpackFromBlocks(a1, rows, cols, dataShare4PrevIDs);


        }
        else{
            // std::cout << "skip SSLJ(X, Y')\n";
        }
        timer.setTimePoint("SSLJ(X, Y') end");

        oc::BitVector memShare4Upd;
        oc::Matrix<oc::u8> dataShare4Upd;

        co_await mSsljSender.send(
            AllIDs, AllPayloads, memShare4Upd, dataShare4Upd, chl);             // SSLJ(X', Y \cup Y'), provide Y \cup Y' with payload

        // T || T^add
        memShare.append(memShare4Upd);                                          
        dataShare.resize(XSize + X_Size, dataShare.cols(), AllocType::Uninitialized);
        std::memcpy(
            dataShare.data(XSize), dataShare4Upd.data(), dataShare4Upd.size());
        timer.setTimePoint("SSLJ(X', Y ∪ Y') end");
        // std::cout << timer << "\n";
    }




}