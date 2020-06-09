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

import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import net.oauth.jsontoken.crypto.AsciiStringSigner;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Signer;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Instant;

import java.security.SignatureException;


/**
 * A JSON Token.
 */
public class JsonToken {
  // header names
  public final static String ALGORITHM_HEADER = "alg";
  public final static String KEY_ID_HEADER = "kid";
  public final static String TYPE_HEADER = "typ";
	
  // standard claim names (payload parameters)
  public final static String ISSUER = "iss";
  public final static String ISSUED_AT = "iat";
  public final static String EXPIRATION = "exp";
  public final static String AUDIENCE = "aud";
  
  // default encoding for all Json token
  public final static String BASE64URL_ENCODING = "base64url";
  
  public final static int DEFAULT_LIFETIME_IN_MINS = 2;

  protected final Clock clock;
  private final JsonObject header;
  private final JsonObject payload;
  private final String tokenString;
  
  // The following fields are only valid when signing the token.
  private final Signer signer;
  private String signature;
  private String baseString;
  
  
  /**
   * Public constructor, use empty data type.
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

    header = new JsonObject();
    header.addProperty(ALGORITHM_HEADER, signer.getSignatureAlgorithm().getNameForJson());
    String keyId = signer.getKeyId();
    if (keyId != null) {
      header.addProperty(KEY_ID_HEADER, keyId);
    }

    this.payload = new JsonObject();
    this.signer = signer;
    this.clock = clock;
    this.signature = null;
    this.baseString = null;
    this.tokenString = null;
    String issuer = signer.getIssuer();
    if (issuer != null) {
      setParam(JsonToken.ISSUER, issuer);
    }
  }

  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken}
   * (as opposed to create a token). This constructor takes Json payload
   * and clock as parameters, set all other signing related parameters to null.
   *
   * @param payload A payload JSON object.
   * @param clock a clock whose notion of current time will determine the not-before timestamp
   *   of the token, if not explicitly set.
   * @param tokenString The original token string we parsed to get this payload.
   */
  public JsonToken(JsonObject header, JsonObject payload, Clock clock, 
      String tokenString) {
    this.header = header;
    this.payload = payload;
    this.clock = clock;
    this.baseString = null;
    this.signature = null;
    this.signer = null;
    this.tokenString = tokenString;
  }
  
  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken}
   * (as opposed to create a token). This constructor takes Json payload
   * as parameter, set all other signing related parameters to null.
   *
   * @param payload A payload JSON object.
   */
  public JsonToken(JsonObject payload) {
    this.header = null;
    this.payload = payload;
    this.baseString = null;
    this.tokenString = null;
    this.signature = null;
    this.signer = null;
    this.clock = null;
  }

  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken}
   * (as opposed to create a token). This constructor takes Json payload
   * and clock as parameters, set all other signing related parameters to null.
   *
   * @param payload A payload JSON object.
   * @param clock a clock whose notion of current time will determine the not-before timestamp
   *   of the token, if not explicitly set.
   */
  public JsonToken(JsonObject payload, Clock clock) {
    this.header = null;
    this.payload = payload;
    this.clock = clock;
    this.baseString = null;
    this.tokenString = null;
    this.signature = null;
    this.signer = null;
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
    String baseString = computeSignatureBaseString();
    String sig = getSignature();
    return JsonTokenUtil.toDotFormat(baseString, sig);
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

  public Instant getIssuedAt() {
    Long issuedAt = getParamAsLong(ISSUED_AT);
    if (issuedAt == null) {
      return null;
    }
    // JWT represents time in seconds, Instants expect milliseconds
    return new Instant(issuedAt * 1000);
  }

  public void setIssuedAt(Instant instant) {
    setParam(JsonToken.ISSUED_AT, instant.getMillis() / 1000);
  }

  public Instant getExpiration() {
    Long expiration = getParamAsLong(EXPIRATION);
    if (expiration == null) {
      return null;
    }
    // JWT represents time in seconds, Instants expect milliseconds
    return new Instant(expiration * 1000);
  }

  public void setExpiration(Instant instant) {
    setParam(JsonToken.EXPIRATION, instant.getMillis() / 1000);
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
    JsonElement element = payload.get(param);
    if (element != null && element.isJsonPrimitive()) {
      return (JsonPrimitive) element;
    }
    return null;
  }
  
  public JsonObject getPayloadAsJsonObject() {
    return payload;
  }
  
  public String getKeyId() {
    if (header == null) {
      return null;
    }

    JsonElement keyIdName = header.get(JsonToken.KEY_ID_HEADER);
    return keyIdName != null ? keyIdName.getAsString() : null;
  }

  public SignatureAlgorithm getSignatureAlgorithm() {
    if (header == null) {
      throw new IllegalStateException("JWT has no algorithm or header");
    }

    JsonElement algorithmName = header.get(JsonToken.ALGORITHM_HEADER);
    if (algorithmName == null) {
      throw new IllegalStateException("JWT header is missing the required '" +
          JsonToken.ALGORITHM_HEADER + "' parameter");
    }
    return SignatureAlgorithm.getFromJsonName(algorithmName.getAsString());
  }

  public String getTokenString() {
    return tokenString;
  }

  public JsonObject getHeader() {
    if (header == null) {
      throw new IllegalStateException("JWT has no header");
    }
    return header;
  }
  
  private String getParamAsString(String param) {
    JsonPrimitive primitive = getParamAsPrimitive(param);
    return primitive == null ? null : primitive.getAsString();
  }

  private Long getParamAsLong(String param) {
    JsonPrimitive primitive = getParamAsPrimitive(param);
    if (primitive != null && (primitive.isNumber() || primitive.isString())) {
      try {
        return primitive.getAsLong();
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return null;
  }
  
  protected String computeSignatureBaseString() {
    if (baseString != null && !baseString.isEmpty()) {
      return baseString;
    }
    baseString = JsonTokenUtil.toDotFormat(
        JsonTokenUtil.toBase64(getHeader()),
        JsonTokenUtil.toBase64(payload)
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
