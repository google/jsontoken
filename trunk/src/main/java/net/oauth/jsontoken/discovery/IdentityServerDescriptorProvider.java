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
 * A {@link ServerDescriptorProvider} that returns the issuer id as the server
 * descriptor. If a JSON Token issuer uses their own server descriptor as their
 * issuer id, then the JSON Token verifier would use this implementation of
 * {@link ServerDescriptorProvider} with the {@link DefaultPublicKeyLocator}.
 *
 * For example, some OAuth Servers might use their Client's server descriptors
 * as client_ids, and then use this implementation of {@link ServerDescriptorProvider}
 * with the {@link DefaultPublicKeyLocator}.
 */
public class IdentityServerDescriptorProvider implements ServerDescriptorProvider {

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.discovery.ServerDescriptorProvider#getServerDescriptor(java.lang.String)
   */
  @Override
  public URI getServerDescriptor(String issuer) {
    return URI.create(issuer);
  }
}
