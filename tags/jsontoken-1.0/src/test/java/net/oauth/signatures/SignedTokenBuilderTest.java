/**
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package net.oauth.signatures;

import net.oauth.jsontoken.JsonTokenTestBase;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;
import net.oauth.jsontoken.crypto.Signer;

import org.joda.time.Instant;

public class SignedTokenBuilderTest extends JsonTokenTestBase {

  public void testSignature() throws Exception {

    Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    SignedOAuthToken token = new SignedOAuthToken(signer);
    token.setMethod("GET");
    token.setNonce("nonce");
    token.setOAuthToken("token");
    token.setAudience("http://www.example.com/api");

    assertEquals("GET", token.getMethod());
    assertEquals("nonce", token.getNonce());
    assertEquals("token", token.getOAuthToken());
    assertEquals("http://www.example.com/api", token.getAudience());

    SignedOAuthTokenParser parser = new SignedOAuthTokenParser(locators, null);
    SignedOAuthToken compare = parser.parseToken(token.serializeAndSign(), "GET", "HTTP://www.Example.Com/api");

    assertEquals("GET", compare.getMethod());
    assertEquals("nonce", compare.getNonce());
    assertEquals("token", compare.getOAuthToken());
    assertEquals("http://www.example.com/api", compare.getAudience());
  }
}
