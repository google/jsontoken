/*
 * Copyright 2010 Google LLC
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
 */
package net.oauth.jsontoken.discovery;

import com.google.common.collect.ImmutableSet;
import java.net.URI;
import java.util.Collection;

/**
 * A {@link ServerDescriptorProvider} that returns the issuer id as the server descriptor for
 * explicitly allowlisted issuers. If a JSON Token issuer uses their own server descriptor as their
 * issuer id, then the JSON Token verifier would use this implementation of {@link
 * ServerDescriptorProvider} with the {@link DefaultPublicKeyLocator}.
 *
 * <p>For example, some OAuth Servers might use their Client's server descriptors as client_ids, and
 * then use this implementation of {@link ServerDescriptorProvider} with the {@link
 * DefaultPublicKeyLocator}.
 */
public class IdentityServerDescriptorProvider implements ServerDescriptorProvider {

  private final ImmutableSet<String> allowedIssuers;

  /**
   * Public constructor.
   *
   * @param allowedIssuers A collection of trusted issuer IDs whose server descriptors may be
   *     resolved.
   */
  public IdentityServerDescriptorProvider(Collection<String> allowedIssuers) {
    this.allowedIssuers = ImmutableSet.copyOf(allowedIssuers);
  }

  /**
   * Public constructor.
   *
   * @param allowedIssuers One or more trusted issuer IDs whose server descriptors may be resolved.
   */
  public IdentityServerDescriptorProvider(String... allowedIssuers) {
    this.allowedIssuers = ImmutableSet.copyOf(allowedIssuers);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.discovery.ServerDescriptorProvider#getServerDescriptor(java.lang.String)
   */
  @Override
  public URI getServerDescriptor(String issuer) {
    if (issuer == null || !allowedIssuers.contains(issuer)) {
      return null;
    }
    return URI.create(issuer);
  }
}
