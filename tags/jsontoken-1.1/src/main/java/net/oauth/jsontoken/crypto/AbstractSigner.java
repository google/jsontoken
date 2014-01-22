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
package net.oauth.jsontoken.crypto;

/**
 * Superclass for {@link Signer}s.
 */
public abstract class AbstractSigner implements Signer {

  private final String issuer;
  private String keyId;

  /**
   * Caller can suggest which key should be used for signing by passing 'suggestedKeyId' to signer.
   * It's up to signer whether to use the suggestedKeyId or not. The final signing key id can be
   * retrieved by calling getKeyId().
   * 
   * @param issuer
   * @param suggestedKeyId
   */
  protected AbstractSigner(String issuer, String suggestedKeyId) {
    this.issuer = issuer;
    this.keyId = suggestedKeyId;
  }
  
  protected void setSigningKeyId(String keyId) {
    this.keyId = keyId;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#getKeyId()
   */
  @Override
  public String getKeyId() {
    return keyId;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#getIssuer()
   */
  @Override
  public String getIssuer() {
    return issuer;
  }
}
