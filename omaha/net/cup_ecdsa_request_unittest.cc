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

// This unit test is hardcoded to run against production servers only.

#include <iostream>
#include <memory>
#include <vector>

#include "omaha/base/constants.h"
#include "omaha/base/string.h"
#include "omaha/base/reg_key.h"
#include "omaha/base/vistautil.h"
#include "omaha/base/security/p256.h"
#include "omaha/net/cup_ecdsa_request.h"
#include "omaha/net/cup_ecdsa_request_impl.h"
#include "omaha/net/cup_ecdsa_utils.h"
#include "omaha/net/network_config.h"
#include "omaha/net/simple_request.h"
#include "omaha/testing/unit_test.h"

namespace omaha {

const TCHAR* const kGetUrl =
    _T("https://updates.") COMPANY_DOMAIN _T("/service/update2/id");
const TCHAR* const kGetUrlNoResponseBody =
    _T("https://updates.") COMPANY_DOMAIN _T("/service/update2/nil");
const TCHAR* const kPostUrl =
    _T("https://updates.") COMPANY_DOMAIN _T("/service/update2");
const TCHAR* const kPostHttpsUrl =
    _T("https://updates.") COMPANY_DOMAIN _T("/service/update2");
const uint8 kRequestBuffer[] =
    "<request protocol=\"3.0\" updaterversion=\"1.3.99.0\" xshell_version=\"1.3.99.0\" ismachine=\"0\""
    " sessionid=\"{00000000-0000-0000-0000-000000000000}\""
    " requestid=\"{00000000-0000-0000-0000-000000000000}\">"
    "<hw physmemory=\"32\" sse=\"1\" sse2=\"1\" sse3=\"1\" ssse3=\"1\" sse41=\"1\" sse42=\"1\" avx=\"1\"/>"
    "<os platform=\"\" version=\"\" sp=\"\" arch=\"x64\"/>"
    "<app appid=\"{00000000-0000-0000-0000-000000000000}\" version=\"\" nextversion=\"\" lang=\"\" brand=\"\" client=\"\">"
    "</app>"
    "</request>";

class CupEcdsaRequestTest : public testing::Test {
 protected:
  CupEcdsaRequestTest() {}

  static void SetUpTestCase() {
    InitializeNetworkConfig();
  }

  static void TearDownTestCase() {
    NetworkConfig* network_config = NULL;
    EXPECT_HRESULT_SUCCEEDED(
        NetworkConfigManager::Instance().GetUserNetworkConfig(&network_config));
    network_config->Clear();
  }

  static void InitializeNetworkConfig() {
    NetworkConfig* network_config = NULL;
    EXPECT_HRESULT_SUCCEEDED(
        NetworkConfigManager::Instance().GetUserNetworkConfig(&network_config));

    EXPECT_HRESULT_SUCCEEDED(network_config->Detect());
  }

  void DoRequest(HttpRequestInterface* contained_request,
                 const CString& url,
                 const uint8* request_buffer,
                 size_t request_buffer_length) {
    // Create a CUP-ECDSA request wrapping the contained request.
    auto http_request = std::make_unique<CupEcdsaRequest>(contained_request);

    // Set up a a direct (non-proxied) connection.
    NetworkConfig* network_config = NULL;
    EXPECT_HRESULT_SUCCEEDED(
        NetworkConfigManager::Instance().GetUserNetworkConfig(&network_config));
    HINTERNET handle = network_config->session().session_handle;
    http_request->set_session_handle(handle);
    http_request->set_proxy_configuration(ProxyConfig());
    http_request->set_url(url);
    if (request_buffer) {
      http_request->set_request_buffer(request_buffer, request_buffer_length);
    }

    // Execute the CUP-ECDSA send, expecting it to succeed.
    // TODO(omaha): Until CUP-ECDSA is checked into the server code, this will
    // instead return OMAHA_NET_E_CUP_NO_SERVER_PROOF (0x80040880).
    EXPECT_HRESULT_SUCCEEDED(http_request->Send());

    // Check that the CUP-ECDSA outer request contains a HTTP success and a
    // valid body.
    int http_status = http_request->GetHttpStatusCode();
    EXPECT_TRUE(http_status == HTTP_STATUS_OK ||
                http_status == HTTP_STATUS_PARTIAL_CONTENT);
    std::vector<uint8> response(http_request->GetResponse());
  }

  bool DoParseServerETag(const CString& etag) {
    internal::EcdsaSignature sig;
    std::vector<uint8> hash;

    return internal::CupEcdsaRequestImpl::ParseServerETag(etag, &sig, &hash);
  }
};

TEST_F(CupEcdsaRequestTest, PostSimpleRequest) {
  if (IsTestRunByLocalSystem()) {
    return;
  }

  DoRequest(new SimpleRequest, kPostUrl,
            kRequestBuffer, arraysize(kRequestBuffer) - 1);
}

TEST_F(CupEcdsaRequestTest, PostSimpleRequestHttps) {
  if (IsTestRunByLocalSystem()) {
    return;
  }

  DoRequest(new SimpleRequest, kPostHttpsUrl,
            kRequestBuffer, arraysize(kRequestBuffer) - 1);
}

#define WEAK_ETAG_PREFIX _T("W/")
#define QUOTE            _T("\"")

#define TEST_VALID_SIG \
    _T("30450221008eb3780a5f2f30201c63b9dd94dbe461baaaae05") \
    _T("739fd30496be3c0e7c2979c4022073241ee9b311b69e2974c5") \
    _T("29753ae8d363cdc89aebfae378773bc13d1e427bfe")

#define TEST_INT56_HEX \
    _T("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd")

#define TEST_INT64_HEX \
    _T("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

#define TEST_INT72_HEX \
    _T("001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

#define TEST_INT64_BAD \
    _T("1234567890abcdef1234567890______1234567890abcdef1234567890abcdef")


TEST_F(CupEcdsaRequestTest, ParseServerETag_Good) {
  // A Strong ETag formatted as S:H.
  EXPECT_TRUE(DoParseServerETag(
      TEST_VALID_SIG _T(":") TEST_INT64_HEX));

  // A Strong ETag formatted as "S:H".
  EXPECT_TRUE(DoParseServerETag(
      QUOTE TEST_VALID_SIG _T(":") TEST_INT64_HEX QUOTE));

  // A Weak ETag formatted as W/S:H.
  EXPECT_TRUE(DoParseServerETag(
      WEAK_ETAG_PREFIX TEST_VALID_SIG _T(":") TEST_INT64_HEX));

  // A Weak ETag formatted as W/"S:H".
  EXPECT_TRUE(DoParseServerETag(
      WEAK_ETAG_PREFIX QUOTE TEST_VALID_SIG _T(":") TEST_INT64_HEX QUOTE));
}

TEST_F(CupEcdsaRequestTest, ParseServerETag_Fail_Empty) {
  EXPECT_FALSE(DoParseServerETag(_T("")));
}

TEST_F(CupEcdsaRequestTest, ParseServerETag_Fail_NoDelims) {
  EXPECT_FALSE(DoParseServerETag(
      TEST_VALID_SIG TEST_INT64_HEX));

  EXPECT_FALSE(DoParseServerETag(
      TEST_VALID_SIG _T(" ") TEST_INT64_HEX));
}

TEST_F(CupEcdsaRequestTest, ParseServerETag_Fail_HashNot256Bits) {
  EXPECT_FALSE(DoParseServerETag(
      TEST_VALID_SIG _T(":") TEST_INT56_HEX));

  EXPECT_FALSE(DoParseServerETag(
      TEST_VALID_SIG _T(":") TEST_INT72_HEX));
}

TEST_F(CupEcdsaRequestTest, ParseServerETag_Fail_HashNotHex) {
  EXPECT_FALSE(DoParseServerETag(
      TEST_VALID_SIG _T(":") TEST_INT64_BAD));
}

}   // namespace omaha


