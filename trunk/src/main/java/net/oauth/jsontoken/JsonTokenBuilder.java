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
package net.oauth.jsontoken;

import java.security.SignatureException;

import org.joda.time.Duration;
import org.joda.time.Instant;

import com.google.common.base.Preconditions;

import net.oauth.jsontoken.crypto.Signer;

public class JsonTokenBuilder<T extends Payload> {

  public static <V extends Payload> JsonTokenBuilder<V> newBuilder() {
    return new JsonTokenBuilder<V>();
  }

  private Signer signer;
  private Instant notBefore;
  private Duration duration;

  private JsonTokenBuilder() {
    // By default, the token starts now
    notBefore = new Instant();
  }

  public JsonTokenBuilder<T> setNotBefore(Instant instant) {
    this.notBefore = instant;
    return this;
  }

  public JsonTokenBuilder<T> setDuration(Duration d) {
    this.duration = d;
    return this;
  }

  public JsonTokenBuilder<T> setSigner(Signer s) {
    this.signer = s;
    return this;
  }

  public JsonToken<T> create(T payload) throws SignatureException {
    Preconditions.checkNotNull(signer, "signer must not be null");
    Preconditions.checkNotNull(notBefore, "notBefore must not be null");
    Preconditions.checkNotNull(duration, "duration must not be null");

    Envelope env = new Envelope();
    env.setIssuer(signer.getSignerId());
    if (signer.getKeyId() != null) {
      env.setKeyId(signer.getKeyId());
    }
    env.setNotBefore(notBefore);
    env.setSignatureAlgorithm(signer.getSignatureAlgorithm());
    env.setTokenLifetime(duration);

    return JsonToken.generateToken(payload, env, signer);
  }
}
