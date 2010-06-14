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

import com.google.common.base.Preconditions;

import net.oauth.jsontoken.Clock;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenBuilder;
import net.oauth.jsontoken.SystemClock;
import net.oauth.jsontoken.crypto.Signer;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class SignedOAuthTokenBuilder {

  private final Signer signer;
  private final Clock clock;

  private Instant notBefore;
  private Duration duration;
  private String uri;
  private String method;
  private String nonce;
  private byte[] requestBody;
  private String token;

  public SignedOAuthTokenBuilder(Signer signer) {
    this(signer, new SystemClock());
  }

  public SignedOAuthTokenBuilder(Signer signer, Clock clock) {
    Preconditions.checkNotNull(signer);
    Preconditions.checkNotNull(clock);
    this.signer = signer;
    this.clock = clock;
  }

  public SignedOAuthTokenBuilder setNotBefore(Instant instant) {
    this.notBefore = instant;
    return this;
  }

  public SignedOAuthTokenBuilder setDuration(Duration d) {
    this.duration = d;
    return this;
  }

  public SignedOAuthTokenBuilder setUri(String audience) {
    this.uri = audience;
    return this;
  }

  public SignedOAuthTokenBuilder setMethod(String m) {
    this.method = m;
    return this;
  }

  public SignedOAuthTokenBuilder setNonce(String n) {
    this.nonce = n;
    return this;
  }

  public SignedOAuthTokenBuilder setRequestBody(byte[] body) {
    this.requestBody = body;
    return this;
  }

  public SignedOAuthTokenBuilder setOAuthToken(String t) {
    this.token = t;
    return this;
  }

  public JsonToken<SignedOAuthTokenPayload> build() throws SignatureException {
    Preconditions.checkNotNull(token, "must set OAuth token");
    Preconditions.checkNotNull(nonce, "must set nonce");
    Preconditions.checkNotNull(uri, "must set URI");
    Preconditions.checkNotNull(method, "must set method");

    SignedOAuthTokenPayload payload = new SignedOAuthTokenPayload();

    JsonTokenBuilder<SignedOAuthTokenPayload> builder = JsonTokenBuilder.newBuilder();
    builder.setSigner(signer);

    if (notBefore == null) {
      builder.setNotBefore(clock.now());
    } else {
      builder.setNotBefore(notBefore);
    }

    if (duration == null) {
      builder.setDuration(Duration.standardMinutes(1));
    } else {
      builder.setDuration(duration);
    }

    if (requestBody != null) {
      payload.setBodyHash(getBodyHash());
    }

    payload.setUri(uri);
    payload.setOAuthToken(token);
    payload.setMethod(method);
    payload.setNonce(nonce);

    return builder.create(payload);
  }

  private String getBodyHash() {
    Preconditions.checkNotNull(requestBody);
    String hashAlg = signer.getSignatureAlgorithm().getHashAlgorithm();
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
