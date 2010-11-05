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
package net.oauth.signatures;

import java.security.SignatureException;

import javax.servlet.http.HttpServletRequest;

import net.oauth.jsontoken.AudienceChecker;
import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.SystemClock;
import net.oauth.jsontoken.discovery.VerifierProviders;

/**
 * Parses signed json assertion.
 */
public class  SignedJsonAssertionTokenParser {
  
  public static String EXPECTED_CONTENT_TYPE = "application/x-www-form-urlencoded";

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
  public SignedJsonAssertionTokenParser(VerifierProviders locators, NonceChecker nonceChecker) {
    this(locators, nonceChecker, new SystemClock());
  }

  /**
   * Public constructor.
   *
   * @param locators an object that provides signature verifiers, based signature algorithm,
   *   as well as on the signer and key ids.
   * @param nonceChecker An optional nonce checker. If not null, then the parser will
   *   call the nonce checker to make sure that the nonce has not been re-used.JsonTokenParser
   * @param clock a clock that has implemented the
   *   {@link Clock#isCurrentTimeInInterval(org.joda.time.Instant, org.joda.time.Duration)} method
   *   with a suitable slack to account for clock skew when checking token validity.
   */
  public SignedJsonAssertionTokenParser(VerifierProviders locators, NonceChecker nonceChecker,
      Clock clock) {
    this.locators = locators;
    this.nonceChecker = nonceChecker;
    this.clock = clock;
  }
  
  /**
   * Extracts the Json assertion from the Http post body and then verifies it.
   * @param request the {@link HttpServletRequest} that contains the signed Json assertion in the
   *   post body.
   * @return the Json assertion object.
   * @throws SignatureException if the signature doesn't check out, or if authentication fails
   *   for other reason.
   */
  public SignedJsonAssertionToken parseToken(HttpServletRequest request) throws SignatureException {      
    if (!request.getContentType().startsWith(EXPECTED_CONTENT_TYPE)) {
      throw new SignatureException("bad content type: " + request.getContentType());
    }
    
    String grantType = request.getParameter(SignedJsonAssertionToken.GRANT_TYPE);
    if (grantType == null || !grantType.equalsIgnoreCase(SignedJsonAssertionToken.GRANT_TYPE_VALUE)) {
      throw new SignatureException("bad grant_type: " + grantType);
    }
    
    String assertionType = request.getParameter(SignedJsonAssertionToken.ASSERTION_TYPE);
    if (assertionType == null || !assertionType.equalsIgnoreCase(SignedJsonAssertionToken.ASSERTION_TYPE_VALUE)) {
      throw new SignatureException("bad assertion_type: " + assertionType);
    }
    
    String assertion = request.getParameter(SignedJsonAssertionToken.ASSERTION);
    if (assertion == null) {
      throw new SignatureException("empty json assertion");
    }
    
    StringBuffer uri = request.getRequestURL();
    if (request.getQueryString() != null) {
      uri.append("?");
      uri.append(request.getQueryString());
    }

    return parseToken(assertion, uri.toString());
  }

  /**
   * Parses the provided signed Json assertion, and then verifies it against the provided HTTP method
   * and audience URI (in addition to checking the signature, and validity period).
   * @param jsonAssertion the signed Json assertion (in serialized form).
   * @param uri the URI against which the token was exercised.
   * @return the signed Json assertion token (deserialized)
   * @throws SignatureException if the signature (or anything else) doesn't check out.
   */
  public SignedJsonAssertionToken parseToken(String jsonAssertion, String uri) throws SignatureException {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new SignedJsonAssertionAudienceChecker(uri));

    SignedJsonAssertionToken token = new SignedJsonAssertionToken(parser.verifyAndDeserialize(jsonAssertion));

    if (nonceChecker != null) {
      nonceChecker.checkNonce(token.getNonce());
    }

    return token;
  }
}