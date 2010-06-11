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
package net.oauth.jsontoken;

import net.oauth.jsontoken.crypto.AsciiStringVerifier;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.security.SignatureException;
import java.util.regex.Pattern;

public class JsonTokenParser {

  private final Clock clock;

  public JsonTokenParser() {
    this(new SystemClock());
  }

  public JsonTokenParser(Clock clock) {
    this.clock = clock;
  }

  public <V extends Payload> JsonToken<V> parseToken(String tokenString, PayloadDeserializer<V> deserializer,
      VerifierProviders locators) throws SignatureException {
    String[] pieces = tokenString.split(Pattern.quote(JsonTokenUtil.DELIMITER));
    if (pieces.length != 3) {
      throw new IllegalArgumentException("token did not have three separate parts");
    }
    String payloadString = pieces[0];
    String envelopeString = pieces[1];
    String signature = pieces[2];

    V payload = deserializer.fromJson(fromBase64ToJsonString(payloadString));
    Envelope env = Envelope.fromJson(fromBase64ToJsonString(envelopeString));

    String baseString = JsonTokenUtil.getBaseString(payloadString, envelopeString);
    Verifier verifier = locators.getKeyLocator(env.getSignatureAlgorithm()).findVerifier(env.getIssuer(), env.getKeyId());
    AsciiStringVerifier asciiVerifier = new AsciiStringVerifier(verifier);
    asciiVerifier.verifySignature(baseString, Base64.decodeBase64(signature));

    if (!clock.isCurrentTimeInInterval(env.getNotBefore(), env.getTokenLifetime())) {
      throw new SignatureException("token is not yet or no longer valid. " +
          "Token start time: " + env.getNotBefore() + ". duration: " + env.getTokenLifetime());
    }

    return new JsonToken<V>(payload, env, signature);
  }

  private static String fromBase64ToJsonString(String source) {
    return StringUtils.newStringUtf8(Base64.decodeBase64(source));
  }
}
