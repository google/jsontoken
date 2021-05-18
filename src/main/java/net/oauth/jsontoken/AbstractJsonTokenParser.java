/*
 * Copyright 2020 Google LLC
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

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.security.SignatureException;
import java.time.Instant;
import java.util.List;
import net.oauth.jsontoken.crypto.AsciiStringVerifier;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.exceptions.ErrorCode;
import net.oauth.jsontoken.exceptions.InvalidJsonTokenException;
import org.apache.commons.codec.binary.Base64;

/**
 * Class that provides common functions used by {@link JsonTokenParser} and {@link
 * AsyncJsonTokenParser}.
 */
abstract class AbstractJsonTokenParser {
  private final Clock clock;
  private final Checker[] checkers;

  /**
   * Creates a new {@link AbstractJsonTokenParser}.
   *
   * @param clock a clock object that will decide whether a given token is currently valid or not.
   * @param checkers an array of checkers that validates the parameters in the JSON token.
   */
  AbstractJsonTokenParser(Clock clock, Checker... checkers) {
    this.clock = Preconditions.checkNotNull(clock);
    this.checkers = checkers;
  }

  /**
   * Decodes the JWT token string into a JsonToken object. Does not perform any validation of
   * headers or claims.
   *
   * @param tokenString The original encoded representation of a JWT
   * @return Unverified contents of the JWT as a JsonToken
   * @throws JsonParseException if the header or payload of tokenString is corrupted
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  final JsonToken deserializeInternal(String tokenString) {
    List<String> pieces = splitTokenString(tokenString);
    String jwtHeaderSegment = pieces.get(0);
    String jwtPayloadSegment = pieces.get(1);

    JsonObject header =
        JsonParser.parseString(JsonTokenUtil.fromBase64ToJsonString(jwtHeaderSegment))
            .getAsJsonObject();
    JsonObject payload =
        JsonParser.parseString(JsonTokenUtil.fromBase64ToJsonString(jwtPayloadSegment))
            .getAsJsonObject();

    return new JsonToken(header, payload, clock, tokenString);
  }

  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims (iat, exp). Does
   * not need VerifierProviders because verifiers are passed in directly.
   *
   * @param jsonToken the token to verify
   * @throws SignatureException when the signature is invalid or if any of the checkers fail
   * @throws IllegalStateException when exp or iat are invalid or if tokenString is not a properly
   *     formatted JWT
   */
  final void verifyInternal(JsonToken jsonToken, List<Verifier> verifiers)
      throws SignatureException {
    if (!signatureIsValidInternal(jsonToken.getTokenString(), verifiers)) {
      throw new SignatureException(
          "Invalid signature for token: " + jsonToken.getTokenString(),
          new InvalidJsonTokenException(ErrorCode.BAD_SIGNATURE));
    }

    Instant issuedAt = jsonToken.getIssuedAt();
    Instant expiration = jsonToken.getExpiration();

    if (issuedAt == null && expiration != null) {
      issuedAt = Instant.EPOCH;
    }

    if (issuedAt != null && expiration == null) {
      // TODO(kak): Should this be Instant.MAX instead?
      expiration = Instant.ofEpochMilli(Long.MAX_VALUE);
    }

    if (issuedAt != null && expiration != null) {
      String errorMessage =
          String.format(
              "Invalid iat and/or exp. iat: %s exp: %s now: %s",
              jsonToken.getIssuedAt(), jsonToken.getExpiration(), clock.now());

      if (issuedAt.isAfter(expiration)) {
        throw new IllegalStateException(
            errorMessage, new InvalidJsonTokenException(ErrorCode.BAD_TIME_RANGE));
      }

      if (!clock.isCurrentTimeInInterval(issuedAt, expiration)) {
        if (clock.now().isAfter(expiration)) {
          throw new IllegalStateException(
              errorMessage, new InvalidJsonTokenException(ErrorCode.EXPIRED_TOKEN));
        } else {
          throw new IllegalStateException(
              errorMessage, new InvalidJsonTokenException(ErrorCode.BAD_TIME_RANGE));
        }
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
   * @param verifiers used to verify the signature. These usually encapsulate secret keys.
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  final boolean signatureIsValidInternal(String tokenString, List<Verifier> verifiers) {
    List<String> pieces = splitTokenString(tokenString);
    byte[] signature = Base64.decodeBase64(pieces.get(2));
    String baseString = JsonTokenUtil.toDotFormat(pieces.get(0), pieces.get(1));

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
    return expiration == null || expiration.isAfter(now);
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
    return issuedAt == null || issuedAt.isBefore(now);
  }

  /**
   * @param tokenString The original encoded representation of a JWT
   * @return Three components of the JWT as an array of strings
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  private List<String> splitTokenString(String tokenString) {
    List<String> pieces = Splitter.on(JsonTokenUtil.DELIMITER).splitToList(tokenString);
    if (pieces.size() != 3) {
      throw new IllegalStateException(
          "Expected JWT to have 3 segments separated by '"
              + JsonTokenUtil.DELIMITER
              + "', but it has "
              + pieces.size()
              + " segments",
          new InvalidJsonTokenException(ErrorCode.MALFORMED_TOKEN_STRING));
    }
    return pieces;
  }
}
