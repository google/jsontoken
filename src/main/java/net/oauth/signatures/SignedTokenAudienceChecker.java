/**
 * Copyright 2020 Google Inc.
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

import net.oauth.jsontoken.Checker;
import net.oauth.jsontoken.JsonToken;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.gson.JsonObject;

/**
 * Audience checker for signed OAuth tokens. For such tokens, the audience in the token
 * is the URL of the accessed resource, and has to match it exactly (save some case-insensitivities
 * in the host name).
 */
public class SignedTokenAudienceChecker implements Checker {

  // URI that the client is accessing, as seen by the server
  private final String serverUri;

  /**
   * Public constructor.
   * @param uri the URI against which the signed OAuth token was exercised.
   */
  public SignedTokenAudienceChecker(String uri) {
    this.serverUri = uri;
  }

  /**
   * @see net.oauth.jsontoken.Checker#check(com.google.gson.JsonObject)
   */
  @Override
  public void check(JsonObject payload) throws SignatureException {
    checkUri(serverUri,
        Preconditions.checkNotNull(
            payload.get(JsonToken.AUDIENCE).getAsString(),
            "Audience cannot be null!"));
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

    if (!Objects.equal(ourUri.getPath(), tokenUri.getPath())) {
      throw new SignatureException("path in token URI (" + tokenUri.getAuthority() + ") is wrong");
    }

    if (!Objects.equal(ourUri.getQuery(), tokenUri.getQuery())) {
      throw new SignatureException("query string in URI (" + tokenUri.getQuery() + ") is wrong");
    }
  }
}
