#include "SSLJ.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"

#ifdef COPROTO_ENABLE_BOOST
#include <coproto/Socket/AsioSocket.h>
#endif

#include <unordered_map>
#include <algorithm>

using namespace oc;
using namespace uppid;

inline oc::block rowAsBlock(oc::MatrixView<const oc::u8> M, oc::u64 i)
{
    if (M.cols() != 16) throw RTE_LOC;
    if (i >= M.rows())  throw RTE_LOC;

    oc::block out;
    std::memcpy(&out, M.data(i), 16);
    return out;
}

template <typename T>
inline void myShuffle(std::vector<T>& v, oc::PRNG& prng)
{
    for (oc::u64 i = 0; i < v.size(); ++i) {
        std::swap(v[i], v[i + (prng.get<oc::u64>() % (v.size() - i))]);
    }
}

void sslj_test(const oc::CLP& cmd)
{
    const u64 nx = cmd.getOr("nx", 1ull << cmd.getOr("nn", 8));
    const u64 ny = cmd.getOr("ny", nx);
    const u64 dataByteSize = cmd.getOr("bs", 16);
    // TODO(?): RsCpsi fails when bs is not a multiple of 8. 
    const double interFrac = cmd.getOr("p", 0.25);

    PRNG prng;
    prng.SetSeed(oc::OneBlock);

    oc::Matrix<oc::u8> D(ny, dataByteSize);
    prng.get<u8>(D.data(), D.size());

    std::vector<oc::block> Y(ny);
    prng.get(Y.data(), ny);

    std::set<oc::block> Yset(Y.begin(), Y.end());
    if (Y.size() != Yset.size()) {
        std::cout << "Y not unique" << std::endl;
        throw RTE_LOC;
    }

    // Receiver vector X, inject intersection
    std::vector<oc::block> X(Y);
    myShuffle(X, prng);
    X.resize(nx);
    u64 itxSize = (u64)(interFrac * (double)std::min(nx, ny));
    for (u64 i = itxSize; i < nx; ++i) {
        X[i] = prng.get<oc::block>();
    }
    std::set<oc::block> Xset(X.begin(), X.end());
    if (X.size() != Xset.size()) {
        std::cout << "X not unique" << std::endl;
        throw RTE_LOC;
    }
    myShuffle(X, prng);

    macoro::thread_pool pool0;
    auto e0 = pool0.make_work();
    pool0.create_thread();
    macoro::thread_pool pool1;
    auto e1 = pool1.make_work();
    pool1.create_thread();

    auto socket = coproto::LocalAsyncSocket::makePair();
    // auto socket = coproto::AsioSocket::makePair();

    socket[0].setExecutor(pool0);
    socket[1].setExecutor(pool1);

    oc::BitVector memShareR;
    oc::BitVector memShareS;
    oc::Matrix<oc::u8> valueShareR;
    oc::Matrix<oc::u8> valueShareS;

    uppid::SsljReceiver recv;
    uppid::SsljSender   send;

    oc::Timer timer0;

    timer0.setTimePoint("start");

    recv.init(dataByteSize, prng.get(), 1ull << 22);
    send.init(dataByteSize, prng.get(), 1ull << 22);

    auto pR = recv.recv(X, memShareR, valueShareR, socket[0]);
    auto pS = send.send(Y, D, memShareS, valueShareS, socket[1]);

    auto r = macoro::sync_wait(
        macoro::when_all_ready(std::move(pR) | macoro::start_on(pool0),
                               std::move(pS) | macoro::start_on(pool1)));
    std::get<0>(r).result();
    std::get<1>(r).result();

    timer0.setTimePoint("sslj");

    ///////// Check
    
    std::unordered_map<oc::block, u64> y2idx;
    for (u64 j = 0; j < ny; ++j) {
        y2idx[Y[j]] = j;
    }

    for (u64 i = 0; i < nx; ++i) {
        if (y2idx.find(X[i]) == y2idx.end()) { // X[i] is not in Y
            if ((memShareR[i] ^ memShareS[i]) != false) {
                throw RTE_LOC;
            }
        }
        else { // X[i] is in Y
            if ((memShareR[i] ^ memShareS[i]) != true) {
                throw RTE_LOC;
            }
            auto j = y2idx[X[i]]; // j s.t. X[i] = Y[j]
            for (u64 b = 0; b < dataByteSize; ++b) {
                const oc::u8 v = valueShareR(i, b) ^ valueShareS(i, b);
                if (v != D(j, b)) {
                    throw RTE_LOC;
                }
            }
        }
    }

    if (cmd.isSet("v")) {
        std::cout << std::endl;
        std::cout << timer0 << std::endl;
        std::cout << "comm " 
                  << double(socket[0].bytesSent())/1024/1024 << " + "
                  << double(socket[1].bytesSent())/1024/1024 << " = "
                  << double(socket[0].bytesSent() + socket[1].bytesSent())/1024/1024
                  << "MB\nx";
    }
}
