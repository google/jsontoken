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

import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

import net.oauth.jsontoken.crypto.AsciiStringSigner;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Signer;

import com.google.common.base.Preconditions;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;


/**
 * A JSON Token.
 */
public class JsonToken {

  // parameters in a JSON token
  public final static String ISSUER = "issuer";
  public final static String KEY_ID = "key_id";
  public final static String SIGNATURE_ALG = "alg";
  public final static String NOT_BEFORE = "not_before";
  public final static String LIFETIME = "token_lifetime";
  public final static String AUDIENCE = "audience";

  private final JsonObject json;
  private final Signer signer;
  private final Clock clock;
  private String signature;

  /**
   * Public constructor.
   * @param signer the signer that will sign the token.
   */
  public JsonToken(Signer signer) {
    this(signer, new SystemClock());
  }

  /**
   * Public constructor.
   * @param signer the signer that will sign the token
   * @param clock a clock whose notion of current time will determine the not-before timestamp
   *   of the token, if not explicitly set.
   */
  public JsonToken(Signer signer, Clock clock) {
    Preconditions.checkNotNull(signer);
    Preconditions.checkNotNull(clock);
    this.json = new JsonObject();
    this.signer = signer;
    this.clock = clock;
    this.signature = null;

    setParam(JsonToken.ISSUER, signer.getIssuer());
    setParam(JsonToken.KEY_ID, signer.getKeyId());
    setParam(JsonToken.SIGNATURE_ALG, signer.getSignatureAlgorithm().getNameForJson());
  }

  /**
   * Public constructor. This constructor is used when parsing tokens from their
   * serialized representation. First, a parser checks the signature on the token, and
   * then uses this constructor (or the equivalent constructor of a subclass) to create
   * the {@link JsonToken} object.
   *
   * @param json A deserialized JSON object.
   */
  public JsonToken(JsonObject json) {
    this.json = json;
    this.signer = null;
    this.clock = null;
    this.signature = null;
  }

  /**
   * Returns the serialized representation of this token, i.e.,
   * <base64(payload)> || "." || <base64(signature)>
   *
   * This is what a client (token issuer) would send to a token verifier over the
   * wire.
   * @throws SignatureException if the token can't be signed.
   */
  public String serializeAndSign() throws SignatureException {
   return
       JsonTokenUtil.toBase64(json)
       + JsonTokenUtil.DELIMITER
       + getSignature();
  }

  /**
   * Returns a human-readable version of the token.
   */
  @Override
  public String toString() {
    String s;
    try {
      s = getSignature();
    } catch (Exception e) {
      s = "<could not calculate signature>";
    }
    return
        JsonTokenUtil.toJson(json)
        + JsonTokenUtil.DELIMITER
        + s;
  }

  public String getIssuer() {
    return getParamAsString(ISSUER);
  }

  public String getKeyId() {
    return getParamAsString(KEY_ID);
  }

  public SignatureAlgorithm getSignatureAlgorithm() {
    String sigAlg = getParamAsString(SIGNATURE_ALG);
    return SignatureAlgorithm.getFromJsonName(sigAlg);
  }

  public Instant getNotBefore() {
    long notBefore = getParamAsLong(NOT_BEFORE);
    return new Instant(notBefore);
  }

  public void setNotBefore(Instant instant) {
    setParam(JsonToken.NOT_BEFORE, instant.getMillis());
  }

  public Duration getTokenLifetime() {
    long lifetime = getParamAsLong(LIFETIME);
    return new Duration(lifetime);
  }

  public void setTokenLifetime(Duration duration) {
    setParam(JsonToken.LIFETIME, duration.getMillis());
  }

  public String getAudience() {
    return getParamAsString(AUDIENCE);
  }

  public void setAudience(String audience) {
    setParam(AUDIENCE, audience);
  }

  public void setParam(String name, String value) {
    json.addProperty(name, value);
  }

  public void setParam(String name, Number value) {
    json.addProperty(name, value);
  }

  public JsonPrimitive getParamAsPrimitive(String param) {
    return json.getAsJsonPrimitive(param);
  }

  public JsonObject getPayloadAsJsonObject() {
    return json;
  }

  private String getParamAsString(String param) {
    JsonPrimitive value = getParamAsPrimitive(param);
    if (value == null) {
      return null;
    } else {
      return value.getAsString();
    }
  }

  private Long getParamAsLong(String param) {
    JsonPrimitive value = getParamAsPrimitive(param);
    if (value == null) {
      return null;
    } else {
      return value.getAsLong();
    }
  }

  private String getSignature() throws SignatureException {
    if (signer == null) {
      throw new SignatureException("can't sign JsonToken with signer.");
    }

    if (signature == null) {
      if (!json.has(JsonToken.NOT_BEFORE)) {

        // Signer and clock are either both null or both not-null
        // so there is no need to check whether clock is not-null.
        setNotBefore(clock.now());
      }

      if (!json.has(JsonToken.LIFETIME)) {
        setTokenLifetime(Duration.standardMinutes(1));
      }

      // now, generate the signature
      String baseString = JsonTokenUtil.toBase64(json);
      AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
      signature = Base64.encodeBase64URLSafeString(asciiSigner.sign(baseString));
    }
    return signature;
  }
}
