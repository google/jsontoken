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
package net.oauth.jsontoken.discovery;

import java.net.URI;

/**
 * Interface that a JSON Token verifier can implement to help
 * with locating public verification keys. If a JSON Token verifier
 * wants to take advantage of the {@link DefaultPublicKeyLocator} implementation,
 * it needs to provide an implementation of this interface to map issuer ids
 * to server descriptors. Server descriptors are URLs that resolve to server
 * info documents (which, among other things, contain public verification keys).
 */
public interface ServerDescriptorProvider {

  /**
   * Returns the server descriptor, given the issuer id present in a JSON Token.
   */
  public URI getServerDescriptor(String issuer);

}
