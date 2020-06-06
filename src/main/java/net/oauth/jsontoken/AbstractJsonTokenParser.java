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

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.oauth.jsontoken.crypto.AsciiStringVerifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Instant;

import javax.annotation.Nullable;
import java.security.SignatureException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Class that provides common functions
 * used by {@link JsonTokenParser} and {@link AsyncJsonTokenParser}.
 */
abstract class AbstractJsonTokenParser {
  private final Clock clock;
  private final Checker[] checkers;

  /**
   * Creates a new {@link AbstractJsonTokenParser}.
   *
   * @param clock a clock object that will decide whether a given token is
   *   currently valid or not.
   * @param checkers an array of checkers that validates the parameters in the JSON token.
   */
  AbstractJsonTokenParser(Clock clock, Checker... checkers) {
    this.clock = Preconditions.checkNotNull(clock);
    this.checkers = checkers;
  }

  /**
   * Decodes the JWT token string into a JsonToken object. Does not perform
   * any validation of headers or claims.
   *
   * @param tokenString The original encoded representation of a JWT
   * @return Unverified contents of the JWT as a JsonToken
   */
  public JsonToken deserialize(String tokenString) {
    String[] pieces = splitTokenString(tokenString);
    String jwtHeaderSegment = pieces[0];
    String jwtPayloadSegment = pieces[1];
    byte[] signature = Base64.decodeBase64(pieces[2]);
    JsonParser parser = new JsonParser();
    JsonObject header = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtHeaderSegment))
        .getAsJsonObject();
    JsonObject payload = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtPayloadSegment))
        .getAsJsonObject();

    JsonToken jsonToken = new JsonToken(header, payload, clock, tokenString);
    return jsonToken;
  }

  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims
   * (iat, exp). Does not need VerifierProviders because verifiers are passed in
   * directly.
   *
   * @param jsonToken the token to verify
   * @throws SignatureException when the signature is invalid
   * @throws IllegalStateException when exp or iat are invalid
   */
  public void verify(JsonToken jsonToken, List<Verifier> verifiers) throws SignatureException {
    if (! signatureIsValid(jsonToken.getTokenString(), verifiers)) {
      throw new SignatureException("Invalid signature for token: " +
          jsonToken.getTokenString());
    }

    Instant issuedAt = jsonToken.getIssuedAt();
    Instant expiration = jsonToken.getExpiration();

    if (issuedAt == null && expiration != null) {
      issuedAt = new Instant(0);
    }

    if (issuedAt != null && expiration == null) {
      expiration = new Instant(Long.MAX_VALUE);
    }

    if (issuedAt != null && expiration != null) {
      if (issuedAt.isAfter(expiration)
          || ! clock.isCurrentTimeInInterval(issuedAt, expiration)) {
        throw new IllegalStateException(String.format("Invalid iat and/or exp. iat: %s exp: %s "
            + "now: %s", jsonToken.getIssuedAt(), jsonToken.getExpiration(), clock.now()));
      }
    }

    if (checkers != null) {
      for (Checker checker : checkers) {
        checker.check(jsonToken.getPayloadAsJsonObject());
      }
    }
  }

  /**
   * Verifies that a JSON Web Token's signature is valid.
   *
   * @param tokenString the encoded and signed JSON Web Token to verify.
   * @param verifiers used to verify the signature. These usually encapsulate
   *        secret keys.
   */
  public boolean signatureIsValid(String tokenString, List<Verifier> verifiers) {
    String[] pieces = splitTokenString(tokenString);
    byte[] signature = Base64.decodeBase64(pieces[2]);
    String baseString = JsonTokenUtil.toDotFormat(pieces[0], pieces[1]);

    boolean sigVerified = false;
    for (Verifier verifier : verifiers) {
      AsciiStringVerifier asciiVerifier = new AsciiStringVerifier(verifier);
      try {
        asciiVerifier.verifySignature(baseString, signature);
        sigVerified = true;
        break;
      } catch (SignatureException e) {
        continue;
      }
    }
    return sigVerified;
  }

  /**
   * Verifies that a JSON Web Token is not expired.
   *
   * @param jsonToken the token to verify
   * @param now the instant to use as point of reference for current time
   * @return false if the token is expired, true otherwise
   */
  public boolean expirationIsValid(JsonToken jsonToken, Instant now) {
    Instant expiration = jsonToken.getExpiration();
    if ((expiration != null) && now.isAfter(expiration)) {
      return false;
    }
    return true;
  }

  /**
   * Verifies that a JSON Web Token was issued in the past.
   *
   * @param jsonToken the token to verify
   * @param now the instant to use as point of reference for current time
   * @return false if the JWT's 'iat' is later than now, true otherwise
   */
  public boolean issuedAtIsValid(JsonToken jsonToken, Instant now) {
    Instant issuedAt = jsonToken.getIssuedAt();
    if ((issuedAt != null) && now.isBefore(issuedAt)) {
      return false;
    }
    return true;
  }

  /**
   * @param tokenString The original encoded representation of a JWT
   * @return Three components of the JWT as an array of strings
   */
  private String[] splitTokenString(String tokenString) {
    String[] pieces = tokenString.split(Pattern.quote(JsonTokenUtil.DELIMITER));
    if (pieces.length != 3) {
      throw new IllegalStateException("Expected JWT to have 3 segments separated by '" +
          JsonTokenUtil.DELIMITER + "', but it has " + pieces.length + " segments");
    }
    return pieces;
  }

  /**
   * Extracts the necessary information to look up verifiers.
   *
   * @param jsonToken the token to verify
   * @return Signature algorithm, issuer, and keyId in an object
   */
  ProviderLookupData getLookupData(JsonToken jsonToken) {
    JsonObject header = jsonToken.getHeader();
    JsonElement keyIdJson = header.get(JsonToken.KEY_ID_HEADER);
    String keyId = (keyIdJson == null) ? null : keyIdJson.getAsString();
    SignatureAlgorithm sigAlg = jsonToken.getSignatureAlgorithm();

    return ProviderLookupData.create(sigAlg, jsonToken.getIssuer(), keyId);
  }

  /**
   * Class that bundles up the necessary data to look up verifiers.
   */
  @AutoValue
  abstract static class ProviderLookupData {
    static ProviderLookupData create(
        @Nullable SignatureAlgorithm sigAlg,
        @Nullable String issuer,
        @Nullable String keyId
    ) {
      return new AutoValue_AbstractJsonTokenParser_ProviderLookupData(sigAlg, issuer, keyId);
    }

    @Nullable abstract SignatureAlgorithm getSigAlg();
    @Nullable abstract String getIssuer();
    @Nullable abstract String getKeyId();
  }

}
