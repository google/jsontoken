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

/**
 * A JSON Token.
 *
 * @param <T> type of the payload object that is embedded in this JSON Token.
 */
public class JsonToken<T extends Payload> {

  private final T payload;
  private final Envelope envelope;
  private final String signature;

  protected JsonToken(T payload, Envelope envelope, String signature) {
    this.payload = payload;
    this.envelope = envelope;
    this.signature = signature;
  }

  /**
   * Returns the payload of this token.
   */
  public T getPayload() {
    return payload;
  }

  /**
   * Returns the envelope for this token.
   */
  public Envelope getEnvelope() {
    return envelope;
  }

  /**
   * Returns the serialized representation of this token, i.e.,
   * <base64(payload)> || "." || <base64(envelope)> || "." || <base64(signature)>
   *
   * This is what a client (token issuer) would send to a token verifier over the
   * wire.
   */
  public String getToken() {
   return JsonTokenUtil.getBaseString(payload, envelope) + signature;
  }

  /**
   * Returns a human-readable version of the token.
   */
  @Override
  public String toString() {
    return
        payload.toJson()
        + JsonTokenUtil.DELIMITER
        + envelope.toJson()
        + JsonTokenUtil.DELIMITER
        + signature;
  }
}
