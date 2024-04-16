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
  Parameter class to generate BFVRNS crypto context
 */

#ifndef __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H__
#define __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H__

#include "scheme/gen-cryptocontext-params.h"

#include <string>
#include <vector>

namespace lbcrypto {

class CryptoContextBFVRNS;

// every CCParams class should include the following forward declaration as there is
// no general CCParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class CCParams;
//====================================================================================================================
template <>
class CCParams<CryptoContextBFVRNS> : public Params {
public:
    CCParams() : Params(BFVRNS_SCHEME) {}
    explicit CCParams(const std::vector<std::string>& vals) : Params(vals) {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to BFVRNS
    //================================================================================================================
    template <typename T = bool>
    void SetScalingTechnique(ScalingTechnique scalTech0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetFirstModSize(usint firstModSize0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetMultiHopModSize(usint multiHopModSize0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetExecutionMode(ExecutionMode executionMode0) {
        DISABLED_FOR_BGVRNS;
    }
    template <typename T = bool>
    void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetNoiseEstimate(double noiseEstimate0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetDesiredPrecision(double desiredPrecision0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetStatisticalSecurity(uint32_t statisticalSecurity0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetNumAdversarialQueries(uint32_t numAdversarialQueries0) {
        DISABLED_FOR_BFVRNS;
    }
    template <typename T = bool>
    void SetInteractiveBootCompressionLevel(COMPRESSION_LEVEL interactiveBootCompressionLevel0) {
        DISABLED_FOR_BFVRNS;
    }
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H__
