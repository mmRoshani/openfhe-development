//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme using the multiparty bootstrapping method with 5 parties
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc                = BinFHEContext();
    int32_t num_of_parties = 5;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD128, LMKCDEY, num_of_parties);  // number of parties is 5

    // Generate the secret key
    auto sk1 = cc.KeyGen();

    // verifying public key encrypt and decrypt without bootstrap
    // Generate the secret, public key pair
    auto pk1 = cc.PubKeyGen(sk1);
    auto kp2 = cc.MultipartyKeyGen(pk1);
    auto kp3 = cc.MultipartyKeyGen(kp2->publicKey);
    auto kp4 = cc.MultipartyKeyGen(kp3->publicKey);
    auto kp5 = cc.MultipartyKeyGen(kp4->publicKey);

    // common lwe public key
    auto kp = kp5;

    // LARGE_DIM specifies the dimension of the output ciphertext
    auto ct1 = cc.Encrypt(kp->publicKey, 1);
    auto ct2 = cc.Encrypt(kp->publicKey, 0);

    // generate RGSW secret key z_1, ..., z_5
    auto z1 = cc.RGSWKeygen();
    auto z2 = cc.RGSWKeygen();
    auto z3 = cc.RGSWKeygen();
    auto z4 = cc.RGSWKeygen();
    auto z5 = cc.RGSWKeygen();

    // distributed generation of RGSW_{z_*}(1)
    // generate a_{crs}

    auto acrs    = cc.Generateacrs();
    auto rgsw1_1 = cc.RGSWEncrypt(acrs, z1, 1, true);
    auto rgsw1_2 = cc.RGSWEncrypt(acrs, z2, 1);
    auto rgsw1_3 = cc.RGSWEncrypt(acrs, z3, 1);
    auto rgsw1_4 = cc.RGSWEncrypt(acrs, z4, 1);
    auto rgsw1_5 = cc.RGSWEncrypt(acrs, z5, 1);

    auto rgsw12   = cc.RGSWEvalAdd(rgsw1_1, rgsw1_2);
    auto rgsw123  = cc.RGSWEvalAdd(rgsw12, rgsw1_3);
    auto rgsw1234 = cc.RGSWEvalAdd(rgsw123, rgsw1_4);
    auto rgsw1    = cc.RGSWEvalAdd(rgsw1234, rgsw1_5);

    // create btkey with RSGW encryption of 1 for every element of the secret
    uint32_t n = sk1->GetElement().GetLength();

    RingGSWACCKey rgswe1 = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    for (int i = 0; i < n; i++) {
        (*rgswe1)[0][0][i] = rgsw1;
    }
    // distributed generation of RGSW_{z_*}(0) will be done while computing the bootstrapping key
    // Sample Program: Step 2: Key Generation

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // generate acrs for rgsw encryptions of 0 for re-randomization
    std::vector<std::vector<std::vector<NativePoly>>> acrs0;
    for (int i = 0; i < num_of_parties; i++) {      // number of iterations in sequence
        for (int j = 0; j < num_of_parties; j++) {  // for gen of encryption of 0 at one iteration
            for (int k = 0; k < n; k++) {           // dimension of secret
                acrs0[i][j][k] = cc.Generateacrs();
            }
        }
    }

    // generate acrs for rgsw encryptions of 0 for automorphism keygen
    uint32_t digitsG = cc.GetParams()->GetRingGSWParams()->GetDigitsG();
    int32_t m_window = 10;  // need to be sure this is the same value in rgsw-acc-lmkcdey.h
    std::vector<std::vector<NativePoly>> acrsauto;
    for (int i = 0; i < digitsG; i++) {
        for (int j = 0; j < m_window + 1; j++) {
            acrsauto[i][j] = cc.Generateacrs();
        }

        // Generate the bootstrapping keys (refresh, switching and public keys)
        cc.MultipartyBTKeyGen(sk1, rgswe1, z1, true, acrsauto, acrs0[1]);

        cc.MultipartyBTKeyGen(kp2->secretKey, cc.GetRefreshKey(), z2, false, acrsauto, acrs0[1], cc.GetSwitchKey());

        cc.MultipartyBTKeyGen(kp3->secretKey, cc.GetRefreshKey(), z3, false, acrsauto, acrs0[2], cc.GetSwitchKey());

        cc.MultipartyBTKeyGen(kp4->secretKey, cc.GetRefreshKey(), z4, false, acrsauto, acrs0[3], cc.GetSwitchKey());

        cc.MultipartyBTKeyGen(kp5->secretKey, cc.GetRefreshKey(), z5, false, acrsauto, acrs0[4], cc.GetSwitchKey());

        // cc.insertRefreshKey(rgswp5);

        std::cout << "Completed the key generation." << std::endl;

        // Sample Program: Step 4: Evaluation

        // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
        LWEPlaintext result1;
        auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

        LWEPlaintext result;

        // decryption check before computation
        std::vector<LWECiphertext> pct;
        auto pct1 = cc.MultipartyDecryptLead(kp1->secretKey, ctAND1);
        auto pct2 = cc.MultipartyDecryptMain(kp2->secretKey, ctAND1);
        auto pct3 = cc.MultipartyDecryptMain(kp3->secretKey, ctAND1);
        auto pct4 = cc.MultipartyDecryptMain(kp4->secretKey, ctAND1);
        auto pct5 = cc.MultipartyDecryptMain(kp5->secretKey, ctAND1);

        pct.push_back(pct1);
        pct.push_back(pct2);
        pct.push_back(pct3);
        pct.push_back(pct4);
        pct.push_back(pct5);

        cc.MultipartyDecryptFusion(pct, &result);
        std::cout << "Result of encrypted ciphertext of 1 = " << result << std::endl;

        std::cout << "Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = " << result << std::endl;

        return 0;
    }
