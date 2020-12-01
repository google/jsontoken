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
package net.oauth.jsontoken;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import javax.annotation.Nullable;
import net.oauth.jsontoken.crypto.AsciiStringSigner;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Signer;
import net.oauth.jsontoken.exceptions.ErrorCode;
import net.oauth.jsontoken.exceptions.InvalidJsonTokenException;
import org.apache.commons.codec.binary.Base64;

/** A JSON Token. */
public class JsonToken {
  // header names
  public static final String ALGORITHM_HEADER = "alg";
  public static final String KEY_ID_HEADER = "kid";
  public static final String TYPE_HEADER = "typ";

  // standard claim names (payload parameters)
  public static final String ISSUER = "iss";
  public static final String ISSUED_AT = "iat";
  public static final String EXPIRATION = "exp";
  public static final String AUDIENCE = "aud";

  // default encoding for all Json token
  public static final String BASE64URL_ENCODING = "base64url";

  public static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(2);

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
   *
   * @param signer the signer that will sign the token.
   */
  public JsonToken(Signer signer) {
    this(signer, new SystemClock());
  }

  /**
   * Public constructor.
   *
   * @param signer the signer that will sign the token
   * @param clock a clock whose notion of current time will determine the not-before timestamp of
   *     the token, if not explicitly set.
   */
  public JsonToken(Signer signer, Clock clock) {
    this.signer = checkNotNull(signer);
    this.clock = checkNotNull(clock);
    this.header = createHeader(signer);
    this.payload = new JsonObject();
    this.signature = null;
    this.baseString = null;
    this.tokenString = null;

    String issuer = signer.getIssuer();
    if (issuer != null) {
      setParam(ISSUER, issuer);
    }
  }

  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken} (as opposed to create a
   * token). This constructor takes Json payload and clock as parameters, set all other signing
   * related parameters to null.
   *
   * @param payload A payload JSON object.
   * @param clock a clock whose notion of current time will determine the not-before timestamp of
   *     the token, if not explicitly set.
   * @param tokenString The original token string we parsed to get this payload.
   */
  public JsonToken(JsonObject header, JsonObject payload, Clock clock, String tokenString) {
    this.header = header;
    this.payload = payload;
    this.clock = clock;
    this.baseString = null;
    this.signature = null;
    this.signer = null;
    this.tokenString = tokenString;
  }

  /**
   * Public constructor used when parsing a JsonToken {@link JsonToken} (as opposed to create a
   * token). This constructor takes Json payload as parameter, set all other signing related
   * parameters to null.
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
   * Public constructor used when parsing a JsonToken {@link JsonToken} (as opposed to create a
   * token). This constructor takes Json payload and clock as parameters, set all other signing
   * related parameters to null.
   *
   * @param payload A payload JSON object.
   * @param clock a clock whose notion of current time will determine the not-before timestamp of
   *     the token, if not explicitly set.
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
   * <p>This is what a client (token issuer) would send to a token verifier over the wire.
   *
   * @throws SignatureException if the token can't be signed.
   */
  public String serializeAndSign() throws SignatureException {
    String baseString = computeSignatureBaseString();
    String sig = getSignature();
    return JsonTokenUtil.toDotFormat(baseString, sig);
  }

  /** Returns a human-readable version of the token. */
  @Override
  public String toString() {
    return JsonTokenUtil.toJson(payload);
  }

  @Nullable
  public String getIssuer() {
    return getParamAsString(ISSUER);
  }

  @Nullable
  public Instant getIssuedAt() {
    return getParamAsInstant(ISSUED_AT);
  }

  /**
   * Sets the {@code iat} (issued at) timestamp parameter.
   *
   * <p><b>Note:</b> sub-second precision is truncated.
   */
  public void setIssuedAt(Instant instant) {
    setParam(ISSUED_AT, instant.getEpochSecond());
  }

  @Nullable
  public Instant getExpiration() {
    return getParamAsInstant(EXPIRATION);
  }

  /**
   * Sets the {@code exp} (expiration) timestamp parameter.
   *
   * <p><b>Note:</b> sub-second precision is truncated.
   */
  public void setExpiration(Instant instant) {
    setParam(EXPIRATION, instant.getEpochSecond());
  }

  @Nullable
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

  @Nullable
  public JsonPrimitive getParamAsPrimitive(String param) {
    JsonElement element = payload.get(param);
    if (element != null && element.isJsonPrimitive()) {
      return (JsonPrimitive) element;
    }
    return null;
  }

  @Nullable
  public JsonObject getPayloadAsJsonObject() {
    return payload;
  }

  @Nullable
  public String getKeyId() {
    if (header == null) {
      return null;
    }

    JsonElement keyIdName = header.get(KEY_ID_HEADER);
    return keyIdName != null ? keyIdName.getAsString() : null;
  }

  /**
   * @throws IllegalStateException if the header does not exist
   * @throws IllegalArgumentException if the signature algorithm is not supported
   */
  public SignatureAlgorithm getSignatureAlgorithm() {
    if (header == null) {
      throw new IllegalStateException("JWT has no algorithm or header");
    }

    JsonElement algorithmName = header.get(ALGORITHM_HEADER);
    if (algorithmName == null) {
      throw new IllegalStateException(
          "JWT header is missing the required '" + ALGORITHM_HEADER + "' parameter",
          new InvalidJsonTokenException(ErrorCode.BAD_HEADER));
    }

    try {
      return SignatureAlgorithm.getFromJsonName(algorithmName.getAsString());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          e.getMessage(), new InvalidJsonTokenException(ErrorCode.UNSUPPORTED_ALGORITHM));
    }
  }

  public String getTokenString() {
    return tokenString;
  }

  /** @throws IllegalStateException if the header does not exist */
  public JsonObject getHeader() {
    if (header == null) {
      throw new IllegalStateException("JWT has no header");
    }
    return header;
  }

  @Nullable
  private String getParamAsString(String param) {
    JsonPrimitive primitive = getParamAsPrimitive(param);
    return primitive == null ? null : primitive.getAsString();
  }

  @Nullable
  private Instant getParamAsInstant(String param) {
    JsonPrimitive primitive = getParamAsPrimitive(param);
    if (primitive != null && (primitive.isNumber() || primitive.isString())) {
      try {
        // JWT represents time in seconds
        return Instant.ofEpochSecond(primitive.getAsLong());
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return null;
  }

  /** @throws IllegalStateException if the header does not exist */
  protected String computeSignatureBaseString() {
    if (baseString != null && !baseString.isEmpty()) {
      return baseString;
    }
    baseString =
        JsonTokenUtil.toDotFormat(
            JsonTokenUtil.toBase64(getHeader()), JsonTokenUtil.toBase64(payload));
    return baseString;
  }

  private static JsonObject createHeader(Signer signer) {
    JsonObject newHeader = new JsonObject();
    SignatureAlgorithm signatureAlgorithm = signer.getSignatureAlgorithm();
    if (signatureAlgorithm != null) {
      newHeader.addProperty(ALGORITHM_HEADER, signatureAlgorithm.getNameForJson());
    }
    String keyId = signer.getKeyId();
    if (keyId != null) {
      newHeader.addProperty(KEY_ID_HEADER, keyId);
    }
    return newHeader;
  }

  /** @throws SignatureException if the signer does not exist */
  private String getSignature() throws SignatureException {
    if (signature != null && !signature.isEmpty()) {
      return signature;
    }

    if (signer == null) {
      throw new SignatureException(
          "can't sign JsonToken with signer",
          new InvalidJsonTokenException(ErrorCode.ILLEGAL_STATE));
    }

    // now, generate the signature
    AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
    return Base64.encodeBase64URLSafeString(asciiSigner.sign(baseString));
  }
}
