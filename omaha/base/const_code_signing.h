// Copyright 2013 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================

// The parameters of the current code signing Authenticode certificates. For
// security reasons, the checks involving Authenticode not only check the
// subject of the certificate but they check that specific certificates have
// been used to sign.
// The SHA256 hashes of the certificate RSA public keys are defined below.

#ifndef OMAHA_BASE_CONST_CODE_SIGNING_H_
#define OMAHA_BASE_CONST_CODE_SIGNING_H_

#include <windows.h>
#include <tchar.h>

namespace omaha {

// The company and organization names expected in the code
// signing certificates which are trusted.
const TCHAR* const kLegacyCertificateSubjectName = _T("Distributive Corp.");
const TCHAR* const kSha1CertificateSubjectName = _T("Distributive Corp.");
const TCHAR* const kSha256CertificateSubjectName = _T("Distributive Corp.");

// The Omaha certificate thumbprint. Used by unit tests.
const TCHAR* const kCertificateThumbprint =
    _T("a3958ae522f3c54b878b20d7b0f63711e08666b2");
const TCHAR* const kSha256CertificateThumbprint =
    _T("2673ea6cc23beffda49ac715b121544098a1284c");

// The SHA256 hash of the Omaha certificate RSA public key.
const TCHAR* const kCertificatePublicKeyHash =
    _T("6cb128676c6d0b49d3e8918bd835888694333da7540a0994261c0ec0b3516f9d");
const TCHAR* const kSha256CertificatePublicKeyHash =
    _T("3e9d92dfb3a046d49f53bab836f387177ac1ec075e8e3dd306b7c1764432f276");

// The hash of public keys that we pin the code signing certificates to.
// For quick identification, the date and thumbprint of the certificates are
// provide below. The hash is the SHA256 hash of the raw certificate RSA public
// key bytes in DER format.
const TCHAR* const kPublicKeyHashes[] = {
    // Distributive Corp. EV code signing (Sectigo Public Code Signing CA EV R36),
    // RSA 4096 on the eToken, valid 2025-07-27 to 2028-07-27.
    // thumbprint=11ad7db717c0264c5a8b917beb63d1038c7c8d49
    // Add the replacement certificate's hash here, and ship that client, before
    // anything is signed with the replacement.
    _T("4133786dfbdb382481ac93aa6fe14222c3540167ca11edc72db30de497dd4f35"),
};

}  // namespace omaha

#endif  // OMAHA_BASE_CONST_CODE_SIGNING_H_
