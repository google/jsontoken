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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SignatureException;

import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.crypto.Signer;

import com.google.common.base.Preconditions;
import com.google.gson.JsonPrimitive;

/**
 * A signed Json Assertion
 */
public class SignedJsonAssertionToken extends JsonToken {
  
  public static final String ASSERTION_TYPE = "assertion_type";
  public static final String ASSERTION_TYPE_VALUE = "http://oauth.net/json-assertion";
  
  public static final String ASSERTION = "assertion";
  
  public static final String GRANT_TYPE = "grant_type";
  public static final String GRANT_TYPE_VALUE = "assertion";
  
  // addition JSON token payload fields for signed json assertion
  public static final String SUBJECT = "subject";
  public static final String SCOPE = "scope";
  public static final String NONCE = "nonce";
  
  public static final String SIGNED_JSON_ASSERTION_DATA_TYPE = "application/oauth-assertion+json";

  public SignedJsonAssertionToken(Signer signer, Clock clock) {
    super(signer, clock, SIGNED_JSON_ASSERTION_DATA_TYPE);
  }

  public SignedJsonAssertionToken(Signer signer) {
    super(signer);
  }
  
  public SignedJsonAssertionToken(JsonToken token) {
    super(token.getPayloadAsJsonObject());
  }

  public String getSubject() {
    JsonPrimitive subjectJson = getParamAsPrimitive(SUBJECT);
    return subjectJson == null ? null : subjectJson.getAsString();
  }

  public void setSubject(String m) {
    setParam(SUBJECT, m);
  }
  
  public String getScope() {
    JsonPrimitive scopeJson = getParamAsPrimitive(SCOPE);
    return scopeJson == null ? null : scopeJson.getAsString();
  }
  
  public void setScope(String scope) {
    setParam(SCOPE, scope);
  }

  public String getNonce() {
    return getParamAsPrimitive(NONCE).getAsString();
  }

  public void setNonce(String n) {
    setParam(NONCE, n);
  }
  
  public String getJsonAssertionPostBody() throws SignatureException {
    StringBuffer buffer = new StringBuffer();
    buffer.append(GRANT_TYPE).append("=").append(GRANT_TYPE_VALUE);
    buffer.append("&");
    buffer.append(ASSERTION_TYPE).append("=").append(ASSERTION_TYPE_VALUE);
    buffer.append("&");
    try {
      buffer.append(ASSERTION).append("=").append(serializeAndSign());
      return URLEncoder.encode(buffer.toString(), "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new SignatureException("unsupported encoding");
    }
  }

  @Override
  public String serializeAndSign() throws SignatureException {
    Preconditions.checkNotNull(getNonce(), "must set nonce");
    return super.serializeAndSign();
  }
}
