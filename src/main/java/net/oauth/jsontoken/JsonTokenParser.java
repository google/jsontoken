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
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProviders;
import org.joda.time.Instant;

import java.security.SignatureException;
import java.util.List;

/**
 * Class that parses and verifies JSON Tokens.
 */
public class JsonTokenParser extends AbstractJsonTokenParser {
  private final VerifierProviders verifierProviders;

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
    super(clock, checkers);
    this.verifierProviders = verifierProviders;
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
    List<Verifier> verifiers = verifierProviders
        .getVerifierProvider(jsonToken.getSignatureAlgorithm())
        .findVerifier(jsonToken.getIssuer(), jsonToken.getKeyId());
    if (verifiers == null) {
      throw new IllegalStateException("No valid verifier for issuer: " + jsonToken.getIssuer());
    }
    return verifiers;
  }

}
