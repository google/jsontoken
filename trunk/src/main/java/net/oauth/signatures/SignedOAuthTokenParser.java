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
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import net.oauth.jsontoken.JsonTokenParser;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicHeaderValueParser;

import com.google.common.base.Objects;

public class SignedOAuthTokenParser {

  private final JsonTokenParser parser;
  private final NonceChecker nonceChecker;

  public SignedOAuthTokenParser(JsonTokenParser parser, NonceChecker nonceChecker) {
    this.parser = parser;
    this.nonceChecker = nonceChecker;
  }

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

  public SignedOAuthToken parseToken(String tokenString, String method, String uri) throws SignatureException {
    SignedOAuthToken token = new SignedOAuthToken(parser.verifyAndDeserialize(tokenString));

    if (!method.equalsIgnoreCase(token.getMethod())) {
      throw new SignatureException("method does not equal in token (" + token.getMethod() + ")");
    }

    checkUri(uri, token.getUri());

    if (nonceChecker != null) {
      nonceChecker.checkNonce(token);
    }

    return token;
  }

  private void checkUri(String ourUriString, String tokenUriString) throws SignatureException {
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
