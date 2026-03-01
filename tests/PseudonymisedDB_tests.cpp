#include "PseudonymisedDB.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"

#define COPROTO_ENABLE_BOOST

#ifdef COPROTO_ENABLE_BOOST
#include <coproto/Socket/AsioSocket.h>
#endif

// #include <coproto/Socket/LocalAsyncSocket.h>

#include <unordered_map>
#include <algorithm>
#include <set>
#include <vector>
#include <iostream>

using namespace oc;
using namespace uppid;

template <typename T>
inline void myShuffle(std::vector<T>& v, oc::PRNG& prng)
{
    for (u64 i = 0; i < v.size(); ++i) {
        std::swap(v[i], v[i + (prng.get<u64>() % (v.size() - i))]);
    }
}

namespace
{

    struct BlockHash
    {
        std::size_t operator()(const oc::block& b) const noexcept
        {
            std::uint64_t w[2];
            static_assert(sizeof(oc::block) == 16, "oc::block must be 16 bytes");
            std::memcpy(w, &b, 16);

            // 간단한 64-bit mix
            std::uint64_t x = w[0] ^ (w[1] + 0x9e3779b97f4a7c15ULL + (w[0] << 6) + (w[0] >> 2));
            return static_cast<std::size_t>(x);
        }
    };

    struct BlockEq
    {
        bool operator()(const oc::block& a, const oc::block& b) const noexcept
        {
            return std::memcmp(&a, &b, 16) == 0;
        }
    };
    
    block sampleFreshBlock(PRNG& prng, const std::set<block>& forbid)
    {
        while (true)
        {
            block x = prng.get<block>();
            if (forbid.find(x) == forbid.end())
                return x;
        }
    }

    void appendRows(Matrix<u8>& dst, const Matrix<u8>& src)
    {
        if (src.rows() == 0) return;

        if (dst.rows() == 0)
        {
            dst.resize(src.rows(), src.cols());
            std::memcpy(dst.data(), src.data(), src.size());
            return;
        }

        if (dst.cols() != src.cols())
            throw RTE_LOC;

        u64 oldRows = dst.rows();
        Matrix<u8> tmp(oldRows + src.rows(), dst.cols());
        std::memcpy(tmp.data(), dst.data(), dst.size());
        std::memcpy(tmp.data(oldRows), src.data(), src.size());
        dst = std::move(tmp);
    }

    void checkCurrentState(
        PseudonymisedDB_P0& db0,
        PseudonymisedDB_P1& db1,
        const std::vector<block>& Xall,
        const std::vector<block>& Yall,
        const Matrix<u8>& Dall,
        u64 dataByteSize)
    {
        auto mem0 = db0.getMemShare();
        auto mem1 = db1.getMemShare();
        auto val0 = db0.getDataShare();
        auto val1 = db1.getDataShare();

        int count = 0;

        if (mem0.size() != mem1.size()) throw RTE_LOC;
        if (val0.rows() != val1.rows() || val0.cols() != val1.cols()) throw RTE_LOC;

        // 현재까지 insert된 X 개수와 share table row 수가 일치해야 함
        // std::cout << "mem0.size() is " << mem0.size() << " Xall.size() is " << Xall.size() << "\n";
        if (mem0.size() != Xall.size()) throw RTE_LOC;
        if (val0.rows() != Xall.size()) throw RTE_LOC;
        if (val0.cols() != dataByteSize) throw RTE_LOC;

        std::unordered_map<block, u64> y2idx;
        y2idx.reserve(Yall.size() * 2 + 1);
        for (u64 j = 0; j < Yall.size(); ++j)
            y2idx[Yall[j]] = j;

        for (u64 i = 0; i < Xall.size(); ++i)
        {
            bool inY = (y2idx.find(Xall[i]) != y2idx.end());
            bool mem = bool(mem0[i] ^ mem1[i]);

            if (mem != inY){
                std::cout << "120line error, i is " << i << " inY is " << inY << " mem is " << mem << '\n';
                throw RTE_LOC;
            }

            if (inY)
            {
                u64 j = y2idx[Xall[i]];
                for (u64 b = 0; b < dataByteSize; ++b)
                {
                    u8 v = val0(i, b) ^ val1(i, b);
                    if (v != Dall(j, b)){
                        std::cout << "i is " << i << '\n';
                        throw RTE_LOC;
                    }
                }
                count++;
            }
            // if (inY == 0) {
            //     // 추가: non-member payload should reconstruct to all-zero
            //     for (u64 b = 0; b < dataByteSize; ++b) {
            //         u8 v = val0(i, b) ^ val1(i, b);
            //         if (v != 0) {
            //             std::cout << "Non-member payload not zero at i=" << i
            //                     << ", b=" << b
            //                     << ", v=" << (u64)v << std::endl;
            //             // throw RTE_LOC;
            //         }
            //     }
            // }
        }
        // std::cout << "Check Correctness: Xall.size is " << Xall.size() << " count is " << count << "\n";
    }

    // X, Y, D 생성:
    // - Y는 unique
    // - X는 일부를 Y와 교집합으로 만들고, 나머지는 fresh
    // - X/Y 모두 "기존 전체 집합"과도 중복되지 않게 생성
    void makeBatch(
        u64 nx,
        u64 ny,
        u64 dataByteSize,
        double interFrac,
        PRNG& prng,
        const std::set<block>& usedXGlobal,
        const std::set<block>& usedYGlobal,
        std::vector<block>& Xout,
        std::vector<block>& Yout,
        Matrix<u8>& Dout)
    {
        Xout.clear();
        Yout.clear();

        Xout.reserve(nx);
        Yout.reserve(ny);

        Dout.resize(ny, dataByteSize);

        // payload 생성
        prng.get<u8>(Dout.data(), Dout.size());

        // ====== Y 생성 (global Y와 disjoint, local unique) ======
        std::unordered_set<block, BlockHash, BlockEq> localY;
        localY.reserve(static_cast<size_t>(ny * 2 + 1));

        while (Yout.size() < ny)
        {
            block y = prng.get<block>();

            // 기존 Y와 겹치면 skip
            if (usedYGlobal.find(y) != usedYGlobal.end())
                continue;

            // 이번 batch 내부 중복이면 skip
            if (!localY.insert(y).second)
                continue;

            Yout.push_back(y);
        }

        // ====== X 생성 ======
        const u64 itxSize = static_cast<u64>(interFrac * static_cast<double>(std::min(nx, ny)));

        Xout.resize(nx);

        // 교집합 부분: Yout에서 랜덤 subset 선택
        std::vector<block> yPerm = Yout;
        myShuffle(yPerm, prng);

        std::unordered_set<block, BlockHash, BlockEq> xLocalUsed;
        xLocalUsed.reserve(static_cast<size_t>(nx * 2 + 1));

        for (u64 i = 0; i < itxSize; ++i)
        {
            Xout[i] = yPerm[i];
            xLocalUsed.insert(Xout[i]);
        }

        // 비-교집합 부분: fresh X 채우기
        // 조건:
        // - usedXGlobal와 disjoint
        // - usedYGlobal와 disjoint
        // - 이번 batch Yout와 disjoint (localY)
        // - 이번 batch Xout 내부 unique (xLocalUsed)
        for (u64 i = itxSize; i < nx; ++i)
        {
            while (true)
            {
                block x = prng.get<block>();

                if (xLocalUsed.find(x) != xLocalUsed.end()) continue;   // 이번 X 중복 방지
                if (localY.find(x) != localY.end()) continue;           // 이번 Y와 겹치지 않게
                if (usedXGlobal.find(x) != usedXGlobal.end()) continue; // 이전 X와 겹치지 않게
                if (usedYGlobal.find(x) != usedYGlobal.end()) continue; // 이전 Y와 겹치지 않게

                Xout[i] = x;
                xLocalUsed.insert(x);
                break;
            }
        }

        // 최종 셔플: 교집합 원소가 앞쪽에 몰리지 않게
        myShuffle(Xout, prng);

    }
}

void pseudonymisedDB_test(const oc::CLP& cmd)
{

    const u64 nx = cmd.getOr("nx", 1ull << cmd.getOr("nn", 10));   // first run size (P0)
    const u64 ny = cmd.getOr("ny", nx);                            // first run size (P1)
    const u64 dataByteSize = cmd.getOr("bs", 16);
    const double interFrac = cmd.getOr("p", 0.25);

    const u64 updates = cmd.getOr("u", 0);                         // # of updates
    const u64 updatenumber = cmd.getOr("n", 1ull << cmd.getOr("un", 10)); // per-update size (for both X/Y)
    // const u64 updatenumber = cmd.getOr("d", 1ull << cmd.getOr("un", 10)) * 52; // armortized Runtime

    std::cout << "updatenumber is " << updatenumber << "\n";
    PRNG prng;
    prng.SetSeed(oc::ZeroBlock);

    oc::Timer timer;
    timer.setTimePoint("start");

    // ====== Generate first-run batch ======
    std::vector<block> X0, Y0;
    Matrix<u8> D0;
    makeBatch(nx, ny, dataByteSize, interFrac, prng, {}, {}, X0, Y0, D0);
    timer.setTimePoint("End makeBatch");

    // 누적 ground truth (원본 ID 기준)
    std::vector<block> Xall = X0;
    std::vector<block> Yall = Y0;
    Matrix<u8> Dall = D0;

    std::set<block> usedX(X0.begin(), X0.end());
    std::set<block> usedY(Y0.begin(), Y0.end());

    // ====== Thread pools ======
    macoro::thread_pool pool0;
    auto e0 = pool0.make_work();
    pool0.create_thread();

    macoro::thread_pool pool1;
    auto e1 = pool1.make_work();
    pool1.create_thread();

    // auto socket = coproto::LocalAsyncSocket::makePair();
    auto socket = coproto::AsioSocket::makePair();

    socket[0].setExecutor(pool0);
    socket[1].setExecutor(pool1);

    // ====== Initialize DBs ======
    PseudonymisedDB_P0 db0(dataByteSize, prng.get(), PrfType::AltMod, 1ull << 20);
    PseudonymisedDB_P1 db1(dataByteSize, prng.get(), PrfType::AltMod, 1ull << 20);


    oc::Timer timer0;
    timer0.setTimePoint("start");
    
    double AccumulateComm = 0;

    // ====== Invoke First Analysis ======
    {
        span<block> Xpart(X0.data(), X0.size());
        span<block> Ypart(Y0.data(), Y0.size());
        MatrixView<u8> Dpart(D0.data(), D0.rows(), D0.cols());

        auto p0_anon = [&]() -> Proto {
            co_await db0.insertID(Xpart, socket[0]);
            co_await db0.respondOPRF(socket[0]);
            co_return;
        };

        auto p1_anon = [&]() -> Proto {
            co_await db1.respondOPRF(socket[1]);
            co_await db1.insertID(Ypart, Dpart, socket[1]);
            co_return;
        };

        auto p0_analysis = [&]() -> Proto {
            co_await db0.shareUpdate_P0(socket[0]);
            co_return;
        };

        auto p1_analysis = [&]() -> Proto {
            co_await db1.shareUpdate_P1(socket[1]);
            co_return;
        };

        // 1) Anon
        auto r1 = macoro::sync_wait(
            macoro::when_all_ready(
                p0_anon() | macoro::start_on(pool0),
                p1_anon() | macoro::start_on(pool1)
            )
        );
        std::get<0>(r1).result();
        std::get<1>(r1).result();
        timer.setTimePoint("Anon");

        // db0.DinsertID(Xpart);
        // db1.DinsertID(Ypart, Dpart);
        // std::cout << "skip OPRF\n";

        
        std::cout << "First Anon Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
        AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
        

        // 2) Analysis
        if (cmd.isSet("an")){
            auto r2 = macoro::sync_wait(
                macoro::when_all_ready(
                    p0_analysis() | macoro::start_on(pool0),
                    p1_analysis() | macoro::start_on(pool1)
                )
            );
        
            std::get<0>(r2).result();
            std::get<1>(r2).result();
            timer.setTimePoint("Analysis");

            std::cout << "First Analysis Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
            AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
        
        }

        
    }

    timer0.setTimePoint("init-done");

    if (cmd.isSet("v"))
        std::cout << timer << "\n";

    // First correctness check
    if (cmd.isSet("an")){
        checkCurrentState(db0, db1, Xall, Yall, Dall, dataByteSize);
    }
    timer.setTimePoint("End Correctness Check");

    // ====== Invoke Update Analysis ======
    for (u64 u = 0; u < updates; ++u)
    {
        oc::Timer timer;

        std::vector<block> Xu, Yu;
        Matrix<u8> Du;

        makeBatch(
            updatenumber, updatenumber, dataByteSize, interFrac,
            prng, usedX, usedY,
            Xu, Yu, Du);

        span<block> Xpart(Xu.data(), Xu.size());
        span<block> Ypart(Yu.data(), Yu.size());
        MatrixView<u8> Dpart(Du.data(), Du.rows(), Du.cols());

        std::cout << "update data size is " << Xu.size() << "\n";

        auto p0_anon = [&]() -> Proto {
            co_await db0.insertID(Xpart, socket[0]);
            co_await db0.respondOPRF(socket[0]);
            co_return;
        };

        auto p1_anon = [&]() -> Proto {
            co_await db1.respondOPRF(socket[1]);
            co_await db1.insertID(Ypart, Dpart, socket[1]);
            co_return;
        };

        auto p0_analysis = [&]() -> Proto {
            co_await db0.shareUpdate_P0(socket[0]);
            co_return;
        };

        auto p1_analysis = [&]() -> Proto {
            co_await db1.shareUpdate_P1(socket[1]);
            co_return;
        };

        timer.setTimePoint("start");

        // 1) Anon
        auto r1 = macoro::sync_wait(
            macoro::when_all_ready(
                p0_anon() | macoro::start_on(pool0),
                p1_anon() | macoro::start_on(pool1)
            )
        );
        std::get<0>(r1).result();
        std::get<1>(r1).result();
        timer.setTimePoint("Anon");

        // if (u == 0 && !cmd.isSet("an")){
        std::cout << "Update Anon Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
        AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
        // }

        // 2) Analysis
        if (cmd.isSet("an")){
            auto r2 = macoro::sync_wait(
                macoro::when_all_ready(
                    p0_analysis() | macoro::start_on(pool0),
                    p1_analysis() | macoro::start_on(pool1)
                )
            );
            std::get<0>(r2).result();
            std::get<1>(r2).result();
            timer.setTimePoint("Analysis");
            if (u == 0){
                std::cout << "Update Analysis Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
                AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
            }
        }

        // std::cout << "Update Analysis Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
        // AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());

        Xall.insert(Xall.end(), Xu.begin(), Xu.end());
        Yall.insert(Yall.end(), Yu.begin(), Yu.end());
        appendRows(Dall, Du);

        usedX.insert(Xu.begin(), Xu.end());
        usedY.insert(Yu.begin(), Yu.end());
        
        timer.setTimePoint(std::to_string(u) + "-th update");

        if (cmd.isSet("v") && u == (updates - 1)){
            std::cout << timer << "\n";
        }

        // 각 update마다 correctness check
        if (cmd.isSet("an"))
            checkCurrentState(db0, db1, Xall, Yall, Dall, dataByteSize);
        
    }

    

    // std::cout << "PseudonymisedDB incremental test passed.\n";

    if (cmd.isSet("v"))
    {
        // std::cout << "\n" << timer << "\n";
        std::cout << "comm "
                  << double(socket[0].bytesSent()) / 1024.0 / 1024.0 << " + "
                  << double(socket[1].bytesSent()) / 1024.0 / 1024.0 << " = "
                  << double(socket[0].bytesSent() + socket[1].bytesSent()) / 1024.0 / 1024.0
                  << "MB\n";
    }
}