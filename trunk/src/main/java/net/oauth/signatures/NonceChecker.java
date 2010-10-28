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

import net.oauth.jsontoken.JsonToken;

import java.security.SignatureException;

/**
 * Receivers of Json Tokens may implement this interface.
 */
public interface NonceChecker {

  /**
   * Throws if the nonce in the {@link JsonToken} has previously been
   * used by the same token issuer.
   */
  public void checkNonce(String nonce) throws SignatureException;

}
