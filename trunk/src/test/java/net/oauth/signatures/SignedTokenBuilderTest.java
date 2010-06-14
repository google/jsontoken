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

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenTestBase;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;
import net.oauth.jsontoken.crypto.Signer;

public class SignedTokenBuilderTest extends JsonTokenTestBase {

  public void testSignature() throws Exception {

    Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    SignedOAuthTokenBuilder builder = new SignedOAuthTokenBuilder(signer);
    JsonToken<SignedOAuthTokenPayload> token = builder
        .setMethod("GET")
        .setNonce("nonce")
        .setOAuthToken("token")
        .setUri("http://www.example.com/api")
        .build();

    System.out.println(token.toString());
    System.out.println(token.getToken());

    assertEquals("GET", token.getPayload().getMethod());
    assertEquals("nonce", token.getPayload().getNonce());
    assertEquals("token", token.getPayload().getOAuthToken());
    assertEquals("http://www.example.com/api", token.getPayload().getUri());

    SignedOAuthTokenParser parser = new SignedOAuthTokenParser(locators);

    JsonToken<SignedOAuthTokenPayload> compare = parser.parseToken(token.getToken());

    assertEquals("GET", compare.getPayload().getMethod());
    assertEquals("nonce", compare.getPayload().getNonce());
    assertEquals("token", compare.getPayload().getOAuthToken());
    assertEquals("http://www.example.com/api", compare.getPayload().getUri());
  }
}
