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

import java.net.URI;
import java.security.SignatureException;

import net.oauth.jsontoken.AudienceChecker;

/**
 * Audience checker for signed Json Assertion.
 */
public class SignedJsonAssertionAudienceChecker implements AudienceChecker {

  // URI that the client is accessing, as seen by the server
  private final String tokenEndpointUri;

  /**
   * Public constructor.
   * @param uri the URI against which the signed OAuth token was exercised.
   */
  public SignedJsonAssertionAudienceChecker(String uri) {
    this.tokenEndpointUri = uri;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.AudienceChecker#checkAudience(java.lang.String)
   */
  @Override
  public void checkAudience(String tokenUri) throws SignatureException {
    checkUri(tokenEndpointUri, tokenUri);
  }

  private static void checkUri(String ourUriString, String tokenUriString) throws SignatureException {
    URI ourUri = URI.create(ourUriString);
    URI tokenUri = URI.create(tokenUriString);

    if (!ourUri.getScheme().equalsIgnoreCase(tokenUri.getScheme())) {
      throw new SignatureException("scheme in token URI (" + tokenUri.getScheme() + ") is wrong");
    }

    if (!ourUri.getAuthority().equalsIgnoreCase(tokenUri.getAuthority())) {
      throw new SignatureException("authority in token URI (" + tokenUri.getAuthority() + ") is wrong");
    }
  }
}
