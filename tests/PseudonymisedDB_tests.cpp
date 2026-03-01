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

            // simple 64-bit mix
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

            if (mem != inY)
                throw RTE_LOC;
            

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

        }

    }

    // Generate X, Y, and D:
    //  - Y is unique (no duplicates).
    //  - Construct X so that some elements intersect with Y, and the rest are fresh.
    //  - Ensure both X and Y are also disjoint from the existing global set.
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

        // generate payload
        prng.get<u8>(Dout.data(), Dout.size());

        // ====== generate Y (disjoint from global Y, local unique) ======
        std::unordered_set<block, BlockHash, BlockEq> localY;
        localY.reserve(static_cast<size_t>(ny * 2 + 1));

        while (Yout.size() < ny)
        {
            block y = prng.get<block>();

            // skip if it already exists in the global Y set
            if (usedYGlobal.find(y) != usedYGlobal.end())
                continue;

            // skip if it is a duplicate within this batch.
            if (!localY.insert(y).second)
                continue;

            Yout.push_back(y);
        }

        // ====== generate X ======
        const u64 itxSize = static_cast<u64>(interFrac * static_cast<double>(std::min(nx, ny)));

        Xout.resize(nx);

        // Intersection part: pick a random subset from Yout.
        std::vector<block> yPerm = Yout;
        myShuffle(yPerm, prng);

        std::unordered_set<block, BlockHash, BlockEq> xLocalUsed;
        xLocalUsed.reserve(static_cast<size_t>(nx * 2 + 1));

        u64 filled = 0;
        for (u64 i = 0; i < ny && filled < itxSize; ++i)
        {
            block cand = yPerm[i];
            if (usedXGlobal.find(cand) != usedXGlobal.end()) continue;
            Xout[filled++] = cand;
            xLocalUsed.insert(cand);
        }

         // Non-intersection part: fill X with fresh elements.
        // Constraints:
        //   - Disjoint from usedXGlobal
        //   - Disjoint from usedYGlobal
        //   - Disjoint from this batch's Yout (localY)
        //   - Unique within this batch's Xout (xLocalUsed)

        for (u64 i = itxSize; i < nx; ++i)
        {
            while (true)
            {
                block x = prng.get<block>();

                if (xLocalUsed.find(x) != xLocalUsed.end()) continue;   // avoid duplicates within this batch's X
                if (localY.find(x) != localY.end()) continue;           // ensure X does not overlap with this batch's Y
                if (usedXGlobal.find(x) != usedXGlobal.end()) continue; // ensure X does not overlap with previous X
                if (usedYGlobal.find(x) != usedYGlobal.end()) continue; // ensure X does not overlap with previous Y

                Xout[i] = x;
                xLocalUsed.insert(x);
                break;
            }
        }

        // Final shuffle: prevent intersection elements from clustering at the front.
        myShuffle(Xout, prng);

    }
}

void pseudonymisedDB_test(const oc::CLP& cmd)
{

    const u64 nx = cmd.getOr("nx", 1ull << cmd.getOr("nn", 10));   // first run size (P0)
    const u64 ny = cmd.getOr("ny", nx);                            // first run size (P1)
    const u64 dataByteSize = cmd.getOr("bs", 16);
    const double interFrac = cmd.getOr("p", 0.25);

    const u64 updates = cmd.getOr("up", 0);                         // # of updates
    const u64 updatenumber = cmd.getOr("d", 1ull << cmd.getOr("un", 10)); // per-update size (for both X/Y)
    // const u64 updatenumber = cmd.getOr("d", 1ull << cmd.getOr("un", 10)) * 52; // for amortized cost measurement

    PRNG prng;
    prng.SetSeed(oc::ZeroBlock);

    oc::Timer timer;

    // ====== Generate first-run batch ======
    std::vector<block> X0, Y0;
    Matrix<u8> D0;
    makeBatch(nx, ny, dataByteSize, interFrac, prng, {}, {}, X0, Y0, D0);

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

    auto socket = coproto::LocalAsyncSocket::makePair();
    // auto socket = coproto::AsioSocket::makePair(); for WAN

    socket[0].setExecutor(pool0);
    socket[1].setExecutor(pool1);

    // ====== Initialize DBs ======
    PseudonymisedDB_P0 db0(dataByteSize, prng.get(), PrfType::AltMod, 1ull << 20);
    PseudonymisedDB_P1 db1(dataByteSize, prng.get(), PrfType::AltMod, 1ull << 20);

    
    double AccumulateComm = 0;
    timer.setTimePoint("start");
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
        timer.setTimePoint("InsertPID");

        if (cmd.isSet("v")){
            std::cout << "DB pseudonymization Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
            AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
        }
        
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
            timer.setTimePoint("UpdatePayload");
            
            if (cmd.isSet("v")){
                std::cout << "DB UpdatePayload Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
                AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
            }
        
        }

        
    }

    // First correctness check
    if (cmd.isSet("an")){
        checkCurrentState(db0, db1, Xall, Yall, Dall, dataByteSize);
    }
    timer.setTimePoint("End Correctness Check");

    // ====== Invoke Update Analysis ======
    for (u64 u = 0; u < updates; ++u)
    {
        // oc::Timer timer;
        // timer.setTimePoint("start");

        std::vector<block> Xu, Yu;
        Matrix<u8> Du;

        makeBatch(
            updatenumber, updatenumber, dataByteSize, interFrac,
            prng, usedX, usedY,
            Xu, Yu, Du);

        span<block> Xpart(Xu.data(), Xu.size());
        span<block> Ypart(Yu.data(), Yu.size());
        MatrixView<u8> Dpart(Du.data(), Du.rows(), Du.cols());

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
        timer.setTimePoint("Update InsertPID");

        if (cmd.isSet("v") && u == 0){
            std::cout << "Update pseudonymization Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
            AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
        }

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
            timer.setTimePoint("UpdatePayload");
            if (cmd.isSet("v") && u == 0){
                std::cout << "Update UpdatePayload Comm is " << (double(socket[0].bytesSent() + socket[1].bytesSent()) - AccumulateComm) / (1024.0 * 1024.0) << '\n';
                AccumulateComm = double(socket[0].bytesSent() + socket[1].bytesSent());
            }
        }

        Xall.insert(Xall.end(), Xu.begin(), Xu.end());
        Yall.insert(Yall.end(), Yu.begin(), Yu.end());
        appendRows(Dall, Du);

        usedX.insert(Xu.begin(), Xu.end());
        usedY.insert(Yu.begin(), Yu.end());

        // if (cmd.isSet("v") && u){
        //     std::cout << timer << "\n";
        // }

        // correctness check
        if (cmd.isSet("an"))
            checkCurrentState(db0, db1, Xall, Yall, Dall, dataByteSize);
        
    }

    if (cmd.isSet("v"))
    {
        std::cout << "\n" << timer << "\n";
        std::cout << "comm "
                  << double(socket[0].bytesSent()) / 1024.0 / 1024.0 << " + "
                  << double(socket[1].bytesSent()) / 1024.0 / 1024.0 << " = "
                  << double(socket[0].bytesSent() + socket[1].bytesSent()) / 1024.0 / 1024.0
                  << "MB\n";
    }
}