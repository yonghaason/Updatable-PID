#include "DoublePrf.h"
#include "cryptoTools/Common/BitVector.h"

#include "Kunlun/mpc/oprf/ddh_oprf.hpp"
#include "Kunlun/crypto/setup.hpp"

using namespace std;
using namespace oc;
using namespace secJoin;

namespace uppid
{

    struct DoublePrf::DdhImpl {
        DDHOPRF::PP pp;
        BigInt dhKey;
    };

    DoublePrf::DoublePrf() = default;
    DoublePrf::~DoublePrf() = default;

    DoublePrf::DoublePrf(DoublePrf&&) noexcept = default;
    DoublePrf& DoublePrf::operator=(DoublePrf&&) noexcept = default;

    void DoublePrf::init(PrfType prfType, oc::block seed,u64 oteBatch)
    {
        mPrfType = prfType;
        mOteBatch = oteBatch;
        mPrng.SetSeed(seed);
        if (prfType == PrfType::AltMod) {
            mAmKey = mPrng.get();
        }
        else {
            mDdh = std::make_unique<DdhImpl>();
            CRYPTO_Initialize();
            mDdh->pp = DDHOPRF::Setup();            
            mDdh->dhKey = GenRandomBigIntLessThan(order);
        }
    };

    Proto DoublePrf::recv(
        oc::span<oc::block> input, 
        std::vector<oc::block>& UID, 
        Socket& chl)
    {
        co_await(chl.send(input.size()));
        UID.resize(input.size());

        if (mPrfType == PrfType::AltMod) {
            AltModPrf altModPrf(mAmKey);
            altModPrf.eval(input, UID);

            CorGenerator ole;
            ole.init(chl.fork(), mPrng, 0, 1, mOteBatch, false);
            oc::SilentOtExtSender keyOtSender;
            std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
            keyOtSender.configure(AltModPrf::KeySize);
            co_await keyOtSender.send(sk, mPrng, chl);

            AltModWPrfReceiver recver;
            recver.init(
                input.size(), ole, 
                AltModPrfKeyMode::SenderOnly, 
                AltModPrfInputMode::ReceiverOnly, 
                {}, sk);
            
            vector<oc::block> OprfMyShare(input.size());
            vector<oc::block> OprfTheirShare(input.size());

            co_await macoro::when_all_ready(
                ole.start(),
                recver.evaluate(input, OprfMyShare, chl, mPrng)
            );

            OprfTheirShare.resize(input.size());
            co_await(chl.recv(OprfTheirShare));

            for (size_t i = 0; i < UID.size(); i++) {
                UID[i] = OprfMyShare[i] ^ OprfTheirShare[i] ^ UID[i];
            }
        }
        else if (mPrfType == PrfType::DDH) {
            // TODO: X25519 Version (See Kunlun/mpc/rpmt/cwprf_mqrpmt.hpp)
            std::vector<__m128i> input_m128(input.size());
            for (size_t i = 0; i < input.size(); i++) {
                input_m128[i] = input[i].mData;
            }
            auto dhKeyByte = mDdh->dhKey.ToByteVector(BN_BYTE_LEN);
            auto myPRF = DDHOPRF::Evaluate(
                mDdh->pp, dhKeyByte, input_m128, input.size());

            BigInt r = GenRandomBigIntLessThan(order); // pick a mask

            std::vector<u8> buffer(input.size() * POINT_BYTE_LEN);
            for(size_t i = 0; i < input.size(); i++) {
                auto maskedInput = Hash::BlockToECPoint(input[i]) * r; // H(x_i)^r
                EC_POINT_point2oct(group, 
                    maskedInput.point_ptr,
                    POINT_CONVERSION_UNCOMPRESSED,
                    buffer.data()+i*POINT_BYTE_LEN,
                    POINT_BYTE_LEN, bn_ctx[0]);
            }
            co_await chl.send(buffer);
            
            std::vector<ECPoint> doublyMaskedInput(input.size());
            co_await chl.recv(buffer);
            for (size_t i = 0; i < input.size(); i++) {
                EC_POINT_oct2point(group, 
                    doublyMaskedInput[i].point_ptr, 
                    buffer.data()+i*POINT_BYTE_LEN, 
                    POINT_BYTE_LEN, 
                    bn_ctx[0]);
            }
            // receive F_k(mask_x_i) from Server

            BigInt r_inverse = r.ModInverse(order); 
            std::vector<ECPoint> oprfInput(input.size());
            vector<vector<u8>> oprf(input.size()); 
            for (size_t i = 0; i < input.size(); i++){
                oprfInput[i] = doublyMaskedInput[i] * r_inverse; 
                oprf[i] = Hash::ECPointToBytes(oprfInput[i]); 
            }
            
            oc::block temp1;
            oc::block temp2;
            for (size_t i = 0; i < myPRF.size(); i++){
                std::memcpy(&temp1, myPRF[i].data(), 16);
                std::memcpy(&temp2 , oprf[i].data(), 16);
                std::memcpy(&UID[i] , (temp1^temp2).data(), 16);
            }
        }
    };

    Proto DoublePrf::send(Socket& chl)
    {
        u64 theirSize;
        co_await(chl.recv(theirSize));

        if (mPrfType == PrfType::AltMod) {
            CorGenerator ole;
            ole.init(chl.fork(), mPrng, 1, 1, mOteBatch, 0);
            oc::SilentOtExtReceiver keyOtReceiver;
            std::vector<oc::block> rk(AltModPrf::KeySize);
            keyOtReceiver.configure(AltModPrf::KeySize);
            oc::BitVector kk_bv;

            kk_bv.append((u8*)mAmKey.data(), AltModPrf::KeySize);

            co_await keyOtReceiver.receive(kk_bv, rk, mPrng, chl);

            AltModWPrfSender sender;
            sender.init(
                theirSize, ole, 
                AltModPrfKeyMode::SenderOnly, 
                AltModPrfInputMode::ReceiverOnly, 
                mAmKey, rk); 

            vector<oc::block> theirOprfShare(theirSize);

            co_await macoro::when_all_ready(
                ole.start(),
                sender.evaluate({}, theirOprfShare, chl, mPrng)
            );

            co_await(chl.send(std::move(theirOprfShare)));
        }   
        else if (mPrfType == PrfType::DDH) {
            // H(x_i)^r, x_i: their input
            std::vector<ECPoint> maskedValue(theirSize); 
            std::vector<u8> buffer;
            co_await chl.recvResize(buffer);
            for (size_t i = 0; i < theirSize; i++) 
            {
                EC_POINT_oct2point(group, 
                    maskedValue[i].point_ptr, 
                    buffer.data()+i*POINT_BYTE_LEN, 
                    POINT_BYTE_LEN, 
                    bn_ctx[0]);
            }

            for (size_t i = 0; i < theirSize; i++){ 
                auto doublyMaskedValue = maskedValue[i] * mDdh->dhKey; // H(x_i)^(rk)
                EC_POINT_point2oct(group, 
                    doublyMaskedValue.point_ptr,
                    POINT_CONVERSION_UNCOMPRESSED,
                    buffer.data()+i*POINT_BYTE_LEN,
                    POINT_BYTE_LEN, bn_ctx[0]);
            }

            co_await chl.send(std::move(buffer));
        }
    };
}