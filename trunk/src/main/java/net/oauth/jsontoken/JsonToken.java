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
	
  // parameters in a json token payload
  public final static String ISSUER = "issuer";
  public final static String NOT_BEFORE = "not_before";
  public final static String NOT_AFTER = "not_after";
  public final static String AUDIENCE = "audience";
  
  // default encoding for all Json token
  public final static String BASE64URL_ENCODING = "base64url";
  
  public final static int DEFAULT_LIFETIME_IN_MINS = 2;

  private final JsonObject payload;
  
  // The following fields are only valid when signing the token.
  private final Signer signer;
  private final Clock clock;
  private final String dataType;
  private final SignatureAlgorithm sigAlg;
  private final String keyIdEncoded;
  private String signature;
  private String baseString;
  
  /**
   * Public constructor, use empty data type.
   * @param signer the signer that will sign the token.
   */
  public JsonToken(Signer signer) {
    this(signer, new SystemClock(), null);
  }

  /**
   * Public constructor.
   * @param signer the signer that will sign the token
   * @param clock a clock whose notion of current time will determine the not-before timestamp
   *   of the token, if not explicitly set.
   * @param dataType
   */
  public JsonToken(Signer signer, Clock clock, String dataType) {
    Preconditions.checkNotNull(signer);
    Preconditions.checkNotNull(clock);
    
    this.payload = new JsonObject();
    this.signer = signer;
    this.clock = clock;
    this.keyIdEncoded = signer.getKeyId();
    this.sigAlg = signer.getSignatureAlgorithm();
    this.dataType = dataType;
    this.signature = null;
    this.baseString = null;
    
    setParam(JsonToken.ISSUER, signer.getIssuer());
  }

  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken} (as opposed to create a token).
   * This constructor takes Json payload as parameter, set all other signing related parameters to null.
   *
   * @param payload A payload JSON object.
   */
  public JsonToken(JsonObject payload) {
    this.payload = payload;
    // when parsing a token, payload is the only field we cares about.
    this.baseString = null;
    this.signature = null;
    this.dataType = null;
    this.sigAlg = null;
    this.keyIdEncoded = null;
    this.signer = null;
    this.clock = null;
  }

  /**
   * Returns the serialized representation of this token, i.e.,
   * keyId.sig.base64(payload).base64(data_type).base64(encoding).base64(alg)
   *
   * This is what a client (token issuer) would send to a token verifier over the
   * wire.
   * @throws SignatureException if the token can't be signed.
   */
  public String serializeAndSign() throws SignatureException {
    computeSignatureBaseString();
    String sig = getSignature();
    return JsonTokenUtil.toDotFormat(keyIdEncoded, sig, baseString);
  }

  /**
   * Returns a human-readable version of the token.
   */
  @Override
  public String toString() {
    return JsonTokenUtil.toJson(payload);
  }

  public String getIssuer() {
    return getParamAsString(ISSUER);
  }

  public Instant getNotBefore() {
    long notBefore = getParamAsLong(NOT_BEFORE);
    return new Instant(notBefore);
  }

  public void setNotBefore(Instant instant) {
    setParam(JsonToken.NOT_BEFORE, instant.getMillis());
  }

  public Instant getNotAfter() {
    long notAfter = getParamAsLong(NOT_AFTER);
    return new Instant(notAfter);
  }

  public void setNotAfter(Instant instant) {
    setParam(JsonToken.NOT_AFTER, instant.getMillis());
  }

  public String getAudience() {
    return getParamAsString(AUDIENCE);
  }

  public void setAudience(String audience) {
    setParam(AUDIENCE, audience);
  }

  public void setParam(String name, String value) {
    payload.addProperty(name, value);
  }

  public void setParam(String name, Number value) {
    payload.addProperty(name, value);
  }

  public JsonPrimitive getParamAsPrimitive(String param) {
    return payload.getAsJsonPrimitive(param);
  }
  
  public JsonObject getPayloadAsJsonObject() {
    return payload;
  }
  
  public String getKeyId() {
    return keyIdEncoded;
  }

  public SignatureAlgorithm getSignatureAlgorithm() {
    return sigAlg;
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
  
  private String computeSignatureBaseString() {
    if (baseString != null && !baseString.isEmpty()) {
      return baseString;
    }
    
	// If lifetime is not set, set to default value.
    if (!payload.has(JsonToken.NOT_BEFORE)) {
      // Signer and clock are either both null or both not-null
      // so there is no need to check whether clock is not-null.
      setNotBefore(clock.now());
    }
    if (!payload.has(JsonToken.NOT_AFTER)) {
      setNotAfter(getNotBefore().plus(Duration.standardMinutes(DEFAULT_LIFETIME_IN_MINS)));
    }
    
    baseString = JsonTokenUtil.toDotFormat(
        JsonTokenUtil.toBase64(payload),
        JsonTokenUtil.convertToBase64(dataType),
        JsonTokenUtil.convertToBase64(BASE64URL_ENCODING),
        JsonTokenUtil.convertToBase64(sigAlg.getNameForJson())
        );
    
    return baseString;
  }

  private String getSignature() throws SignatureException {
    if (signature != null && !signature.isEmpty()) {
      return signature;
    }
    
    if (signer == null) {
      throw new SignatureException("can't sign JsonToken with signer.");
    }
    String signature;
    // now, generate the signature
    AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
    signature = Base64.encodeBase64URLSafeString(asciiSigner.sign(baseString));
    
    return signature;
  }
}
