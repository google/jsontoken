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
 * it needs to provide an implementation of this interface to fetch and parse
 * server info documents. The implementation should if possible recognize
 * different encodings of the server info document (e.g., JSON and XML).
 */
public interface ServerInfoResolver {

  /**
   * Fetches and parses a server info document.
   * @param serverDescriptor the URL from which the server info document
   *   should be fetched.
   * @return an object representing the server info document.
   */
  public ServerInfo resolve(URI serverDescriptor);

}
