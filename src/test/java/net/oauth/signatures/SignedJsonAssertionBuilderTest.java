/*
 * Copyright 2010 Google LLC
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
 */
package net.oauth.signatures;

import net.oauth.jsontoken.JsonTokenTestBase;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;
import net.oauth.jsontoken.crypto.Signer;

public class SignedJsonAssertionBuilderTest extends JsonTokenTestBase {

  public void testSignature() throws Exception {

    Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    SignedJsonAssertionToken token = new SignedJsonAssertionToken(signer);
    token.setNonce("nonce");
    token.setAudience("http://www.example.com/api");
    token.setScope("scope");

    assertEquals("nonce", token.getNonce());
    assertEquals("http://www.example.com/api", token.getAudience());

    SignedJsonAssertionTokenParser parser = new SignedJsonAssertionTokenParser(locators, null);
    SignedJsonAssertionToken compare =
        parser.parseToken(token.serializeAndSign(), "HTTP://www.Example.Com/api");

    assertEquals("nonce", compare.getNonce());
    assertEquals("http://www.example.com/api", compare.getAudience());
  }
}
