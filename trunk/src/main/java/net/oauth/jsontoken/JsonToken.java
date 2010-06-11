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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.security.SignatureException;
import java.util.regex.Pattern;

public class JsonToken<T extends Payload> {

  static private final String DELIMITER = ".";

  private final T payload;
  private final Envelope envelope;
  private final String signature;

  public static <V extends Payload> JsonToken<V> parseToken(String tokenString, PayloadDeserializer<V> deserializer,
      Verifier verifier) throws SignatureException {
    String[] pieces = tokenString.split(Pattern.quote(DELIMITER));
    if (pieces.length != 3) {
      throw new IllegalArgumentException("token did not have three separate parts");
    }
    String payloadString = pieces[0];
    String envelopeString = pieces[1];
    String signature = pieces[2];

    String baseString = getBaseString(payloadString, envelopeString);
    AsciiStringVerifier asciiVerifier = new AsciiStringVerifier(verifier);
    asciiVerifier.verifySignature(baseString, fromBase64ToBytes(signature));

    V payload = deserializer.fromJson(fromBase64ToJsonString(payloadString));
    Envelope env = Envelope.fromJson(fromBase64ToJsonString(envelopeString));

    return new JsonToken<V>(payload, env, signature);
  }

  public static <V extends Payload> JsonToken<V> generateToken(V payload, Envelope env, Signer signer) {
    String baseString = getBaseString(payload, env);
    AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
    String signature = toBase64(asciiSigner.sign(baseString));
    return new JsonToken<V>(payload, env, signature);
  }

  private JsonToken(T payload, Envelope envelope, String signature) {
    this.payload = payload;
    this.envelope = envelope;
    this.signature = signature;
  }

  public T getPayload() {
    return payload;
  }

  public Envelope getEnvelope() {
    return envelope;
  }

  private static String toBase64(byte[] source) {
    return Base64.encodeBase64URLSafeString(source);
  }

  private static String jsonToBase64(String source) {
    return toBase64(StringUtils.getBytesUtf8(source));
  }

  private static byte[] fromBase64ToBytes(String source) {
    return Base64.decodeBase64(source);
  }

  private static String fromBase64ToJsonString(String source) {
    return StringUtils.newStringUtf8(fromBase64ToBytes(source));
  }

  private static String getBaseString(Payload payload, Envelope envelope) {
    return getBaseString(jsonToBase64(payload.toJson()), jsonToBase64(envelope.toJson()));
  }

  private static String getBaseString(String payload, String envelope) {
    return payload + DELIMITER + envelope + DELIMITER;
  }

  public String getToken() {
   return getBaseString(payload, envelope) + signature;
  }

  @Override
  public String toString() {
    return payload.toJson() + DELIMITER + envelope.toJson() + DELIMITER + signature;
  }
}
