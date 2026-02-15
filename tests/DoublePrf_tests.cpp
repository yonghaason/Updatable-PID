#include "DoublePrf_tests.h"
#include "DoublePrf.h"
#ifdef COPROTO_ENABLE_BOOST
#include <coproto/Socket/AsioSocket.h>
#endif

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace std;
using namespace oc;
using namespace uppid;

void doublePrf_AltMod_test(const oc::CLP& cmd)
{       
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    
    PRNG prng;
    prng.SetSeed(oc::ZeroBlock);

    vector<oc::block> X(n);
    vector<oc::block> Y(n);
    prng.get(X.data(), n);
    prng.get(Y.data(), n);

    macoro::thread_pool pool0;
    auto e0 = pool0.make_work();
    pool0.create_thread();
    macoro::thread_pool pool1;
    auto e1 = pool1.make_work();
    pool1.create_thread();

    // LocalAsyncSocket: Fake network. No interaction
    // AsioSocket: Interaction using localhost (requires boost library)
    auto socket = coproto::LocalAsyncSocket::makePair(); 
    // auto socket = coproto::AsioSocket::makePair();
    
    socket[0].setExecutor(pool0);
    socket[1].setExecutor(pool1);
    
    oc::Timer timer0;
    oc::Timer timer1;
        
    DoublePrf party0;
    DoublePrf party1;
    party0.setTimer(timer0);
    party1.setTimer(timer1);

    party0.init(uppid::PrfType::AltMod, prng.get());
    party1.init(uppid::PrfType::AltMod, prng.get());

    vector<oc::block> UID0(n);
    vector<oc::block> UID1(n);
    
    timer0.setTimePoint("start");
    timer1.setTimePoint("start");
    
    auto p0 = party0.recv(X, UID0, socket[0]);
    auto p1 = party1.send(socket[1]);

    auto r = macoro::sync_wait(
        macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
                            
    std::get<0>(r).result();
    std::get<1>(r).result();

    timer0.setTimePoint("X oprf");
    timer1.setTimePoint("X oprf");
    
    auto pp0 = party0.send(socket[0]);
    auto pp1 = party1.recv(Y, UID1, socket[1]);

    auto rr = macoro::sync_wait(
        macoro::when_all_ready(std::move(pp0) | macoro::start_on(pool0),
                            std::move(pp1) | macoro::start_on(pool1)));
    std::get<0>(rr).result();
    std::get<1>(rr).result();

    timer0.setTimePoint("Y oprf");
    timer1.setTimePoint("Y oprf");

    const u64 n_update = prng.get<u64>() % n;
    std::vector<oc::block> X_update(n_update);

    std::vector<u64> y_idx(n_update, u64(-1));

    for (u64 i = 0; i < n_update; ++i) {
        if (prng.getBit()) {
            const u64 j = prng.get<u64>() % n;
            X_update[i] = Y[j];
            y_idx[i] = j;
        }
        else {
            X_update[i] = prng.get<oc::block>();
        }
    }

    std::vector<oc::block> UID_update(n_update);

    auto pu0 = party0.recv(X_update, UID_update, socket[0]);
    auto pu1 = party1.send(socket[1]);

    auto ru = macoro::sync_wait(
        macoro::when_all_ready(std::move(pu0) | macoro::start_on(pool0),
                                std::move(pu1) | macoro::start_on(pool1)));
    std::get<0>(ru).result();
    std::get<1>(ru).result();

    timer0.setTimePoint("Update " + to_string(n_update));
    timer1.setTimePoint("Update " + to_string(n_update));

    // Check: if X_update[i] came from Y[j], UID_update[i] must match UID1[j]
    for (u64 i = 0; i < n_update; ++i)
    {
        if (y_idx[i] != u64(-1))
        {
            if (UID_update[i] != UID1[y_idx[i]])
                throw RTE_LOC;
        }
    }
   
    if (cmd.isSet("v")) {
        cout << endl;
        cout << timer0 << endl;
        // cout << timer1 << endl;

        std::cout << "comm " 
        << double(socket[0].bytesSent())/ 1024 / 1024 << " + "
        << double(socket[1].bytesSent())/ 1024 / 1024 << " = "
        << double(socket[0].bytesSent() + socket[1].bytesSent()) / 1024 / 1024
        << "MB" << std::endl;
    }
}

void doublePrf_DDH_test(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));

    PRNG prng;
    prng.SetSeed(oc::ZeroBlock);

    vector<oc::block> X(n);
    vector<oc::block> Y(n);
    prng.get(X.data(), n);
    prng.get(Y.data(), n);

    macoro::thread_pool pool0;
    auto e0 = pool0.make_work();
    pool0.create_thread();
    macoro::thread_pool pool1;
    auto e1 = pool1.make_work();
    pool1.create_thread();

    // LocalAsyncSocket: Fake network. No interaction
    // AsioSocket: Interaction using localhost (requires boost library)
    auto socket = coproto::LocalAsyncSocket::makePair(); 
    // auto socket = coproto::AsioSocket::makePair();
    
    socket[0].setExecutor(pool0);
    socket[1].setExecutor(pool1);
    
    oc::Timer timer0;
    oc::Timer timer1;
        
    DoublePrf party0;
    DoublePrf party1;
    party0.setTimer(timer0);
    party1.setTimer(timer1);

    party0.init(uppid::PrfType::DDH, prng.get());
    party1.init(uppid::PrfType::DDH, prng.get());

    vector<oc::block> UID0(n);
    vector<oc::block> UID1(n);
    
    timer0.setTimePoint("start");
    timer1.setTimePoint("start");
    
    auto p0 = party0.recv(X, UID0, socket[0]);
    auto p1 = party1.send(socket[1]);

    auto r = macoro::sync_wait(
        macoro::when_all_ready(std::move(p0) | macoro::start_on(pool0),
                            std::move(p1) | macoro::start_on(pool1)));
                            
    std::get<0>(r).result();
    std::get<1>(r).result();

    timer0.setTimePoint("X oprf");
    timer1.setTimePoint("X oprf");
    
    auto pp0 = party0.send(socket[0]);
    auto pp1 = party1.recv(Y, UID1, socket[1]);

    auto rr = macoro::sync_wait(
        macoro::when_all_ready(std::move(pp0) | macoro::start_on(pool0),
                            std::move(pp1) | macoro::start_on(pool1)));
    std::get<0>(rr).result();
    std::get<1>(rr).result();

    timer0.setTimePoint("Y oprf");
    timer1.setTimePoint("Y oprf");

    const u64 n_update = prng.get<u64>() % n;
    std::vector<oc::block> X_update(n_update);

    std::vector<u64> y_idx(n_update, u64(-1));

    for (u64 i = 0; i < n_update; ++i) {
        if (prng.getBit()) {
            const u64 j = prng.get<u64>() % n;
            X_update[i] = Y[j];
            y_idx[i] = j;
        }
        else {
            X_update[i] = prng.get<oc::block>();
        }
    }

    std::vector<oc::block> UID_update(n_update);

    auto pu0 = party0.recv(X_update, UID_update, socket[0]);
    auto pu1 = party1.send(socket[1]);

    auto ru = macoro::sync_wait(
        macoro::when_all_ready(std::move(pu0) | macoro::start_on(pool0),
                                std::move(pu1) | macoro::start_on(pool1)));
    std::get<0>(ru).result();
    std::get<1>(ru).result();

    timer0.setTimePoint("Update " + to_string(n_update));
    timer1.setTimePoint("Update " + to_string(n_update));

    // Check: if X_update[i] came from Y[j], UID_update[i] must match UID1[j]
    for (u64 i = 0; i < n_update; ++i)
    {
        if (y_idx[i] != u64(-1))
        {
            if (UID_update[i] != UID1[y_idx[i]])
                throw RTE_LOC;
        }
    }

    if (cmd.isSet("v")) {
        cout << endl;
        cout << timer0 << endl;
        // cout << timer1 << endl;

        std::cout << "comm " 
        << double(socket[0].bytesSent())/ 1024 / 1024 << " + "
        << double(socket[1].bytesSent())/ 1024 / 1024 << " = "
        << double(socket[0].bytesSent() + socket[1].bytesSent()) / 1024 / 1024
        << "MB" << std::endl;
    }
}