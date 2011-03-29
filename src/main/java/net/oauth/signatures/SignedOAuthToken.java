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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;

import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.crypto.Signer;

import com.google.common.base.Preconditions;

/**
 * A signed OAuth token.
 */
public class SignedOAuthToken extends JsonToken {

  public static final String AUTH_METHOD = "Token";
  public static final String SIGNED_TOKEN_PARAM = "signed_token";

  // addition JSON token payload fields for signed OAuth tokens
  public static final String METHOD = "method";
  public static final String BODY_HASH = "body_hash";
  public static final String OAUTH_TOKEN = "token";
  public static final String NONCE = "nonce";
  
  public SignedOAuthToken(Signer signer, Clock clock) {
    super(signer, clock);
  }

  public SignedOAuthToken(Signer signer) {
    super(signer);
  }
  
  public SignedOAuthToken(JsonToken token) {
    super(token.getPayloadAsJsonObject());
  }

  public String getMethod() {
    return getParamAsPrimitive(METHOD).getAsString();
  }

  public void setMethod(String m) {
    setParam(METHOD, m);
  }

  public String getBodyHash() {
    return getParamAsPrimitive(BODY_HASH).getAsString();
  }

  public void setRequestBody(byte[] body) {
    setParam(BODY_HASH, getBodyHash(body));
  }

  public String getOAuthToken() {
    return getParamAsPrimitive(OAUTH_TOKEN).getAsString();
  }

  public void setOAuthToken(String t) {
    setParam(OAUTH_TOKEN, t);
  }

  public String getNonce() {
    return getParamAsPrimitive(NONCE).getAsString();
  }

  public void setNonce(String n) {
    setParam(NONCE, n);
  }

  public String getAuthorizationHeader() throws SignatureException {
    return AUTH_METHOD + " " + SIGNED_TOKEN_PARAM + "=" + serializeAndSign();
  }

  @Override
  public String serializeAndSign() throws SignatureException {
    Preconditions.checkNotNull(getOAuthToken(), "must set OAuth token");
    Preconditions.checkNotNull(getNonce(), "must set nonce");
    Preconditions.checkNotNull(getAudience(), "must set Audience");
    Preconditions.checkNotNull(getMethod(), "must set method");
    return super.serializeAndSign();
  }

  private String getBodyHash(byte[] requestBody) {
    Preconditions.checkNotNull(requestBody);
    String hashAlg = getSignatureAlgorithm().getHashAlgorithm();
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance(hashAlg);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("platform is missing hash algorithm: " + hashAlg);
    }
    byte[] hash = digest.digest(requestBody);
    return Base64.encodeBase64URLSafeString(hash);
  }
}