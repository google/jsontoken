
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
package net.oauth.signatures;

import java.security.SignatureException;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.JsonParseException;
import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.SystemClock;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicHeaderValueParser;

/**
 * Parses signed OAuth tokens.
 */
public class SignedOAuthTokenParser {

  private final VerifierProviders locators;
  private final NonceChecker nonceChecker;
  private final Clock clock;

  /**
   * Public constructor.
   *
   * @param locators an object that provides signature verifiers, based signature algorithm,
   *   as well as on the signer and key ids.
   * @param nonceChecker An optional nonce checker. If not null, then the parser will
   *   call the nonce checker to make sure that the nonce has not been re-used.
   */
  public SignedOAuthTokenParser(VerifierProviders locators, NonceChecker nonceChecker) {
    this(locators, nonceChecker, new SystemClock());
  }

  /**
   * Public constructor.
   *
   * @param locators an object that provides signature verifiers, based signature algorithm,
   *   as well as on the signer and key ids.
   * @param nonceChecker An optional nonce checker. If not null, then the parser will
   *   call the nonce checker to make sure that the nonce has not been re-used.
   * @param clock a clock that has implemented the
   *   {@link Clock#isCurrentTimeInInterval(org.joda.time.Instant, org.joda.time.Duration)} method
   *   with a suitable slack to account for clock skew when checking token validity.
   */
  public SignedOAuthTokenParser(VerifierProviders locators, NonceChecker nonceChecker, Clock clock) {
    this.locators = locators;
    this.nonceChecker = nonceChecker;
    this.clock = clock;
  }

  /**
   * Extracts the signed OAuth token from the Authorization header and then verifies it.
   * @param request the {@link HttpServletRequest} that contains the signed OAuth token in the
   *   Authorization header.
   * @return the signed OAuth token.
   * @throws SignatureException if the signature doesn't check out, or if authentication fails
   *   for other reason (missing Authorization header, etc.).
   * @throws JsonParseException if the header or payload of tokenString is corrupted
   * @throws IllegalArgumentException if the signature algorithm is not supported
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   *   or if there is no valid verifier for the issuer
   */
  public SignedOAuthToken parseToken(HttpServletRequest request) throws SignatureException {

    // this guaranteed to return a string starting with "Token", or null
    String header = getAuthHeader(request);

    if (header == null) {
       throw new SignatureException("missing Authorization header of type 'Token'");
    }

    String postFix = header.substring(0, SignedOAuthToken.AUTH_METHOD.length()); // read past "Token"
    NameValuePair nvp = BasicHeaderValueParser.parseNameValuePair(postFix.trim(), null);

    if (nvp == null) {
      throw new SignatureException("missing signed_token in Authorization header: " + header);
    }

    if (!SignedOAuthToken.SIGNED_TOKEN_PARAM.equals(nvp.getName())) {
      // Not logging the header in this case. maybe they just mis-spelled "token", but did send the
      // actual OAuth token. We don't want to log that.
      throw new SignatureException("missing signed_token in Authorization header");
    }

    String token = nvp.getValue().trim();

    String method = request.getMethod();

    StringBuffer uri = request.getRequestURL();

    if (request.getQueryString() != null) {
      uri.append("?");
      uri.append(request.getQueryString());
    }

    return parseToken(token, method, uri.toString());
  }

  /**
   * Parses the provided signed OAuth token, and then verifies it against the provided HTTP method
   * and audience URI (in addition to checking the signature, and validity period).
   * @param tokenString the signed OAuth token (in serialized form).
   * @param method the HTTP method that was used when the token was exercised.
   * @param uri the URI against which the token was exercised.
   * @return the signed OAuth token (deserialized)
   * @throws SignatureException if the signature (or anything else) doesn't check out.
   * @throws JsonParseException if the header or payload of tokenString is corrupted
   * @throws IllegalArgumentException if the signature algorithm is not supported
   * @throws IllegalStateException if tokenString is not a properly formatted JWT
   *   or if there is no valid verifier for the issuer
   */
  public SignedOAuthToken parseToken(String tokenString, String method, String uri) throws SignatureException {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new SignedTokenAudienceChecker(uri));

    SignedOAuthToken token = new SignedOAuthToken(parser.verifyAndDeserialize(tokenString));

    if (!method.equalsIgnoreCase(token.getMethod())) {
      throw new SignatureException("method does not equal in token (" + token.getMethod() + ")");
    }

    if (nonceChecker != null) {
      nonceChecker.checkNonce(token.getNonce());
    }

    return token;
  }

  private String getAuthHeader(HttpServletRequest request) {
    @SuppressWarnings("unchecked")
    Enumeration<String> authHeaders = request.getHeaders("Authorization");

    if (authHeaders == null) {
      return null;
    }

    while (authHeaders.hasMoreElements()) {
      String header = (String) authHeaders.nextElement();
      if (header.trim().startsWith(SignedOAuthToken.AUTH_METHOD)) {
        return header.trim();
      }
    }

    return null;
  }
}
