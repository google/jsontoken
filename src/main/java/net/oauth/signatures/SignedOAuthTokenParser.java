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

import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.DefaultPayloadDeserializer;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.PayloadDeserializer;
import net.oauth.jsontoken.discovery.VerifierProviders;

import java.security.SignatureException;

public class SignedOAuthTokenParser extends JsonTokenParser {

  private final PayloadDeserializer<SignedOAuthTokenPayload> deserializer =
      DefaultPayloadDeserializer.newDeserializer(SignedOAuthTokenPayload.class);

  public SignedOAuthTokenParser(Clock clock, VerifierProviders locators) {
    super(clock, locators);
  }

  public SignedOAuthTokenParser(VerifierProviders locators) {
    super(locators);
  }

  public JsonToken<SignedOAuthTokenPayload> parseToken(String tokenString) throws SignatureException {
    JsonToken<SignedOAuthTokenPayload> token = super.parseToken(tokenString, deserializer);

    // TODO: check method, URI, nonce.

    return token;
  }
}
