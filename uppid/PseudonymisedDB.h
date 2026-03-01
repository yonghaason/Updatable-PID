#pragma once
#include "DoublePrf.h"
#include "SsLeftJoin.h"

namespace uppid
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;
    
    // P_0 has set X
    // P_1 has set Y along with associated payload p_y

    class PseudonymisedDB_P0 : oc::TimerAdapter
    { 
        // TODO: Key만 갖고 있는게 더 예쁘긴 함
        DoublePrf           mDoublePrf;
        SsLeftJoinReceiver  mSsljReceiver;
        SsLeftJoinSender    mSsljSender;

        oc::u64 mPartyIdx;

        std::vector<oc::block> UID;
        oc::Matrix<oc::u8> myData;
        
        oc::BitVector memShare;
        oc::Matrix<oc::u8> dataShare;

    public:
        PseudonymisedDB_P0(
            oc::u64 dataByteSize,
            oc::block randomSeed = oc::ZeroBlock,
            PrfType prfType = PrfType::AltMod,
            oc::u64 oteBatchSize = 1ull << 22);

        Proto respondOPRF(Socket& chl);

        Proto insertID(
            oc::span<oc::block> input, 
            // oc::MatrixView<oc::u8> inputData,
            Socket& chl);
        
        void DinsertID(
            oc::span<oc::block> input
        );
        
        // Update memShare, dataShare 
        Proto shareUpdate_P0(Socket& chl);
        
        std::vector<oc::block>&  getUID() {return UID;};
        oc::Matrix<oc::u8>&      getData() {return myData;};

        oc::BitVector&           getMemShare() {return memShare;};
        oc::Matrix<oc::u8>&      getDataShare() {return dataShare;};
    };

    class PseudonymisedDB_P1 : oc::TimerAdapter
    {
        // TODO: Key만 갖고 있는게 더 예쁘긴 함
        DoublePrf           mDoublePrf;
        SsLeftJoinReceiver  mSsljReceiver;
        SsLeftJoinSender    mSsljSender;

        oc::u64 mPartyIdx;

        std::vector<oc::block> UID;
        oc::Matrix<oc::u8> myData;
        
        oc::BitVector memShare;
        oc::Matrix<oc::u8> dataShare;

        oc::u64 YSize = 0;

    public:
        PseudonymisedDB_P1(
            oc::u64 dataByteSize,
            oc::block randomSeed = oc::ZeroBlock,
            PrfType prfType = PrfType::AltMod,
            oc::u64 oteBatchSize = 1ull << 22);

        Proto respondOPRF(Socket& chl);

        Proto insertID(
            oc::span<oc::block> input,
            oc::MatrixView<oc::u8> inputData,
            Socket& chl);

        void DinsertID(
            oc::span<oc::block> input,
            oc::MatrixView<oc::u8> inputData
        );
        
        // Update memShare, dataShare 
        Proto shareUpdate_P1(Socket& chl);

        std::vector<oc::block>&  getUID() {return UID;};
        oc::Matrix<oc::u8>&      getData() {return myData;};

        oc::BitVector&           getMemShare() {return memShare;};
        oc::Matrix<oc::u8>&      getDataShare() {return dataShare;};
    };
}