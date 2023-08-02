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
  FHEW scheme (RingGSW accumulator) implementation
  The scheme is described in https://eprint.iacr.org/2014/816 and in Daniele Micciancio and Yuriy Polyakov
  "Bootstrapping in FHEW-like Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
  https://eprint.iacr.org/2020/086.

  Full reference to https://eprint.iacr.org/2014/816:
  @misc{cryptoeprint:2014:816,
    author = {Leo Ducas and Daniele Micciancio},
    title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
    howpublished = {Cryptology ePrint Archive, Report 2014/816},
    year = {2014},
    note = {\url{https://eprint.iacr.org/2014/816}},
 */

#include "rgsw-acc.h"

#include <string>

namespace lbcrypto {

// SignedDigitDecompose is a bottleneck operation
// There are two approaches to do it.
// The current approach appears to give the best performance
// results. The two variants are labeled A and B.
void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const {
    uint32_t N                           = params->GetN();
    uint32_t digitsG                     = params->GetDigitsG();
    NativeInteger Q                      = params->GetQ();
    NativeInteger QHalf                  = Q >> 1;
    NativeInteger::SignedNativeInt Q_int = Q.ConvertToInt();

    NativeInteger::SignedNativeInt baseG = NativeInteger(params->GetBaseG()).ConvertToInt();

    NativeInteger::SignedNativeInt gBits = (NativeInteger::SignedNativeInt)std::log2(baseG);

    // VARIANT A
    NativeInteger::SignedNativeInt gBitsMaxBits = NativeInteger::MaxBits() - gBits;

    // VARIANT B
    // NativeInteger::SignedNativeInt gminus1 = (1 << gBits) - 1;
    // NativeInteger::SignedNativeInt baseGdiv2 =
    // (baseG >> 1)-1;

    // Signed digit decomposition
    for (size_t j = 0; j < 2; ++j) {
        for (size_t k = 0; k < N; ++k) {
            const NativeInteger& t           = input[j][k];
            NativeInteger::SignedNativeInt d = (t < QHalf) ? t.ConvertToInt() : (t.ConvertToInt() - Q_int);

            for (size_t l = 0; l < digitsG; ++l) {
                // remainder is signed
                // VARIANT A: This approach gives a slightly better performance
                NativeInteger::SignedNativeInt r = d << gBitsMaxBits;
                r >>= gBitsMaxBits;

                // VARIANT B
                // NativeInteger::SignedNativeInt r = d & gminus1;
                // if (r > baseGdiv2) r -= baseG;

                d -= r;
                d >>= gBits;

                if (r < 0)
                    r += Q_int;

                output[j + 2 * l][k] += r;
            }
        }
    }
}

// Decompose a ring element, not ciphertext
void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& input, std::vector<NativePoly>& output) const {
    uint32_t N                           = params->GetN();
    uint32_t digitsG                     = params->GetDigitsG();
    NativeInteger Q                      = params->GetQ();
    NativeInteger QHalf                  = Q >> 1;
    NativeInteger::SignedNativeInt Q_int = Q.ConvertToInt();

    NativeInteger::SignedNativeInt baseG = NativeInteger(params->GetBaseG()).ConvertToInt();

    NativeInteger::SignedNativeInt gBits = (NativeInteger::SignedNativeInt)std::log2(baseG);

    // VARIANT A
    NativeInteger::SignedNativeInt gBitsMaxBits = NativeInteger::MaxBits() - gBits;

    // Signed digit decomposition
    for (size_t k = 0; k < N; ++k) {
        const NativeInteger& t           = input[k];
        NativeInteger::SignedNativeInt d = (t < QHalf) ? t.ConvertToInt() : (t.ConvertToInt() - Q_int);

        for (size_t l = 0; l < digitsG; ++l) {
            // remainder is signed
            NativeInteger::SignedNativeInt r = d << gBitsMaxBits;
            r >>= gBitsMaxBits;

            d -= r;
            d >>= gBits;

            if (r < 0)
                r += Q_int;

            output[l][k] += r;
        }
    }
}

RingGSWEvalKey RingGSWAccumulator::RGSWBTEvalMult(const std::shared_ptr<RingGSWCryptoParams> params,
                                                  RingGSWEvalKey prevbtkey, int32_t si) const {
    auto polyParams   = params->GetPolyParams();
    uint32_t N        = params->GetN();
    uint32_t digitsG  = params->GetDigitsG();
    auto modulus      = params->GetQ();
    uint32_t digitsG2 = digitsG << 1;
    prevbtkey->SetFormat(COEFFICIENT);
    auto newbtkey = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    for (uint32_t i = 0; i < digitsG2; i++) {
        for (uint32_t j = 0; j < 2; j++) {
            (*prevbtkey)[i][j].SetFormat(COEFFICIENT);
            (*newbtkey)[i][j] = NativePoly(polyParams, COEFFICIENT, true);
            for (uint32_t k = 0; k < N; k++) {
                (*newbtkey)[i][j][k] = (*prevbtkey)[i][j][k];
            }
        }
    }
    // initiate with si and skNTT
    bool clockwise = true;
    if (si < 0) {
        clockwise = false;
    }

    if (clockwise) {
        si = (N)-si;
    }
    else {
        si = -si;
    }
    auto mod = si % (N);

// std::cout << "si mod N in mult: " << mod << std::endl;
// std::cout << "mod Q in mult: " << modulus << std::endl;
#if 0
    // perform the multiplication
    for (uint32_t i = 0; i < digitsG2; i++) {
        for (uint32_t j = 0; j < 2; j++) {
            (*prevbtkey)[i][j].SetFormat(COEFFICIENT);
            (*newbtkey)[i][j] = NativePoly(polyParams, COEFFICIENT, true);
            for (uint32_t k = 0; k < N; k++) {
                int32_t res = (mod + k) % N;
                if (!clockwise) {
                    if (res < si) {
                        (*newbtkey)[i][j][k] = -(*prevbtkey)[i][j][res];
                    }
                    else {
                        (*newbtkey)[i][j][k] = (*prevbtkey)[i][j][res];
                    }
                }
                else {
                    if (res < si) {
                        (*newbtkey)[i][j][k] = (*prevbtkey)[i][j][res];
                    }
                    else {
                        (*newbtkey)[i][j][k] = -(*prevbtkey)[i][j][res];
                    }
                }
            }
            (*newbtkey)[i][j].SetFormat(EVALUATION);
        }
    }
#endif
    // std::cout << "before loop " << (*newbtkey)[0][0][0] << std::endl;
    // std::cout << "before loop prev " << (*prevbtkey)[0][0][0] << std::endl;
    for (uint32_t i = 0; i < digitsG; i++) {
        // std::cout << "original poly0: " << (*prevbtkey)[2 * i][0] << std::endl;
        for (uint32_t k = 0; k < N; k++) {
            int32_t res = (mod + k) % N;
            if (!clockwise) {
                if (res < si) {
                    (*newbtkey)[2 * i][0][k]     = modulus - (*prevbtkey)[2 * i][0][res];
                    (*newbtkey)[2 * i + 1][1][k] = modulus - (*prevbtkey)[2 * i + 1][1][res];
                }
                else {
                    (*newbtkey)[2 * i][0][k]     = (*prevbtkey)[2 * i][0][res];
                    (*newbtkey)[2 * i + 1][1][k] = (*prevbtkey)[2 * i + 1][1][res];
                }
            }
            else {
                if (res < si) {
                    (*newbtkey)[2 * i][0][k]     = (*prevbtkey)[2 * i][0][res];
                    (*newbtkey)[2 * i + 1][1][k] = (*prevbtkey)[2 * i + 1][1][res];
                }
                else {
                    (*newbtkey)[2 * i][0][k]     = modulus - (*prevbtkey)[2 * i][0][res];
                    (*newbtkey)[2 * i + 1][1][k] = modulus - (*prevbtkey)[2 * i + 1][1][res];
                }
            }
        }
        // std::cout << "si mod N in mult: " << mod << std::endl;
        // std::cout << "original poly0: " << (*prevbtkey)[2 * i][0] << std::endl;
        // std::cout << "rotated poly0: " << (*newbtkey)[2 * i][0] << std::endl;
        // std::cout << "original poly1: " << (*prevbtkey)[2 * i + 1][1] << std::endl;
        // std::cout << "rotated poly1: " << (*newbtkey)[2 * i + 1][1] << std::endl;
    }

    // std::cout << "after loop" << std::endl;

    newbtkey->SetFormat(EVALUATION);
    prevbtkey->SetFormat(EVALUATION);
    return newbtkey;
}
};  // namespace lbcrypto
