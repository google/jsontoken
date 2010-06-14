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

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

import com.google.common.base.Preconditions;

import net.oauth.jsontoken.crypto.AsciiStringSigner;
import net.oauth.jsontoken.crypto.Signer;

/**
 * Class that can create a signed JSON Token.
 *
 * @param <T> type of the payload that is to be included in the JSON Token.
 */
public class JsonTokenBuilder<T extends Payload> {

  /**
   * Returns a new {@link JsonTokenBuilder} for the specified payload type.
   */
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

  /**
   * Set the start of the validity interval for the JSON Token. If not called,
   * the token will start at the instant the {@link JsonTokenBuilder} was created.
   */
  public JsonTokenBuilder<T> setNotBefore(Instant instant) {
    this.notBefore = instant;
    return this;
  }

  /**
   * Set the duration of the validity interval for the JSON Token. You have to
   * call this method.
   */
  public JsonTokenBuilder<T> setDuration(Duration d) {
    this.duration = d;
    return this;
  }

  /**
   * Set the signer that will sign the JSON Token. You have to call this method.
   */
  public JsonTokenBuilder<T> setSigner(Signer s) {
    this.signer = s;
    return this;
  }

  /**
   * Create a token with the provided payload.
   * @throws SignatureException if the signer could not be used to create a signature.
   */
  public JsonToken<T> create(T payload) throws SignatureException {
    Preconditions.checkNotNull(signer, "signer must not be null");
    Preconditions.checkNotNull(notBefore, "notBefore must not be null");
    Preconditions.checkNotNull(duration, "duration must not be null");

    Envelope env = new Envelope();
    if (signer.getKeyId() != null) {
      env.setKeyId(signer.getKeyId());
    }
    env.setIssuer(signer.getIssuer());
    env.setNotBefore(notBefore);
    env.setTokenLifetime(duration);
    env.setSignatureAlgorithm(signer.getSignatureAlgorithm());

    // now, generate the signature
    String baseString = JsonTokenUtil.getBaseString(payload, env);
    AsciiStringSigner asciiSigner = new AsciiStringSigner(signer);
    String signature = Base64.encodeBase64URLSafeString(asciiSigner.sign(baseString));
    return new JsonToken<T>(payload, env, signature);
  }
}
