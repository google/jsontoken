/**
 * Copyright 2020 Google Inc.
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

import com.google.common.collect.Lists;

import net.oauth.jsontoken.crypto.RsaSHA256Verifier;
import net.oauth.jsontoken.crypto.Verifier;

import java.net.URI;
import java.util.List;

/**
 * Default strategy for locating public verification keys. Unlike secret (symmetric)
 * verification keys, public verification keys can be published by token issuers
 * at URLs called "server descriptors".
 *
 * The default strategy to find a public verification key consists of first mapping
 * an issuer id to a server descriptor, and then fetching the ServerInfo document from
 * the server descriptor URL. Finally, the key is looked up int the ServerInfo document
 * by key id.
 */
public class DefaultPublicKeyLocator implements VerifierProvider {

  private final ServerDescriptorProvider descriptorProvider;
  private final ServerInfoResolver descriptorResolver;

  /**
   * Public constructor.
   *
   * @param descriptorProvider A {@link ServerDescriptorProvider} that maps
   *   issuer ids to server descriptors (URLs).
   * @param resolver A {@link ServerInfoResolver}, i.e., an object that can fetch
   *   and parse a server info document, given a server descriptor.
   */
  public DefaultPublicKeyLocator(ServerDescriptorProvider descriptorProvider,
      ServerInfoResolver resolver) {
    this.descriptorProvider = descriptorProvider;
    this.descriptorResolver = resolver;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.discovery.VerifierProvider#findVerifier(java.lang.String, java.lang.String)
   */
  @Override
  public List<Verifier> findVerifier(String issuer, String keyId) {
    URI serverDescriptor = descriptorProvider.getServerDescriptor(issuer);
    Verifier rsaVerifier = 
      new RsaSHA256Verifier(descriptorResolver.resolve(serverDescriptor).getVerificationKey(keyId));
    return Lists.newArrayList(rsaVerifier);
  }
}
