/**
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
 *
 */
package net.oauth.jsontoken;

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import net.oauth.jsontoken.crypto.AsciiStringVerifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProviders;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.Instant;
import java.security.SignatureException;
import java.util.List;

/**
 * Class that parses and verifies JSON Tokens.
 */
public class JsonTokenParser {

  private final Clock clock;
  private final VerifierProviders verifierProviders;
  private final Checker[] checkers;

  /**
   * Creates a new {@link JsonTokenParser} with a default system clock. The default
   * system clock tolerates a clock skew of up to {@link SystemClock#DEFAULT_ACCEPTABLE_CLOCK_SKEW}.
   *
   * @param verifierProviders an object that provides signature verifiers
   *   based on a signature algorithm, the signer, and key ids.
   * @param checker an audience checker that validates the audience in the JSON token.
   */
  public JsonTokenParser(VerifierProviders verifierProviders, Checker checker) {
    this(new SystemClock(), verifierProviders, checker);
  }

  /**
   * Creates a new {@link JsonTokenParser}.
   *
   * @param clock a clock object that will decide whether a given token is
   *   currently valid or not.
   * @param verifierProviders an object that provides signature verifiers
   *   based on a signature algorithm, the signer, and key ids.
   * @param checkers an array of checkers that validates the parameters in the JSON token.
   */
  public JsonTokenParser(Clock clock, VerifierProviders verifierProviders, Checker... checkers) {
    this.clock = Preconditions.checkNotNull(clock);
    this.verifierProviders = verifierProviders;
    this.checkers = checkers;
  }
  
  /**
   * Decodes the JWT token string into a JsonToken object. Does not perform
   * any validation of headers or claims.
   * 
   * @param tokenString The original encoded representation of a JWT
   * @return Unverified contents of the JWT as a JsonToken
   * @throws JsonParseException if the header or payload of tokenString is corrupted
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  public JsonToken deserialize(String tokenString) {
    List<String> pieces = splitTokenString(tokenString);
    String jwtHeaderSegment = pieces.get(0);
    String jwtPayloadSegment = pieces.get(1);
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
   * (iat, exp). Uses VerifierProviders to obtain the secret key.
   * 
   * @param jsonToken
   * @throws SignatureException when the signature is invalid
   *   or if any of the checkers fail
   * @throws IllegalArgumentException if the signature algorithm is not supported
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   *   or if there is no valid verifier for the issuer
   *   or if the header does not exist
   */
  public void verify(JsonToken jsonToken) throws SignatureException {
    List<Verifier> verifiers = provideVerifiers(jsonToken);
    verify(jsonToken, verifiers);
  }

  /**
   * Parses, and verifies, a JSON Token.
   * 
   * @param tokenString the serialized token that is to parsed and verified.
   * @return the deserialized {@link JsonObject}, suitable for passing to the constructor
   *   of {@link JsonToken} or equivalent constructor of {@link JsonToken} subclasses.
   * @throws SignatureException when the signature is invalid
   *   or if any of the checkers fail
   * @throws JsonParseException if the header or payload portion of tokenString is corrupted
   * @throws IllegalArgumentException if the signature algorithm is not supported
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   *   or if there is no valid verifier for the issuer
   */
  public JsonToken verifyAndDeserialize(String tokenString) throws SignatureException {
    JsonToken jsonToken = deserialize(tokenString);
    verify(jsonToken);
    return jsonToken;
  }
  
  /**
   * Verifies that the jsonToken has a valid signature and valid standard claims
   * (iat, exp). Does not need VerifierProviders because verifiers are passed in
   * directly.
   * 
   * @param jsonToken the token to verify
   * @throws SignatureException when the signature is invalid
   *   or if any of the checkers fail
   * @throws IllegalStateException when exp or iat are invalid
   *   or if tokenString is not a properly formatted JWT
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
   *   secret keys.
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  public boolean signatureIsValid(String tokenString, List<Verifier> verifiers) {
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
   * Use VerifierProviders to get a list of verifiers for this token
   * 
   * @param jsonToken
   * @return list of verifiers
   * @throws IllegalArgumentException if the signature algorithm is not supported
   * @throws IllegalStateException if there is no valid verifier for the issuer
   *   or if the header does not exist
   */
  private List<Verifier> provideVerifiers(JsonToken jsonToken) {
    Preconditions.checkNotNull(verifierProviders);
    String keyId = jsonToken.getKeyId();
    SignatureAlgorithm sigAlg = jsonToken.getSignatureAlgorithm();
    List<Verifier> verifiers = verifierProviders.getVerifierProvider(sigAlg)
        .findVerifier(jsonToken.getIssuer(), keyId);
    if (verifiers == null) {
      throw new IllegalStateException("No valid verifier for issuer: " + jsonToken.getIssuer());
    }
    return verifiers;
  }

  /**
   * @param tokenString The original encoded representation of a JWT
   * @return Three components of the JWT as an array of strings
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   */
  private List<String> splitTokenString(String tokenString) {
    List<String> pieces = Splitter.on(JsonTokenUtil.DELIMITER).splitToList(tokenString);
    if (pieces.size() != 3) {
      throw new IllegalStateException("Expected JWT to have 3 segments separated by '" + 
          JsonTokenUtil.DELIMITER + "', but it has " + pieces.size() + " segments");
    }
    return pieces;
  }
}
