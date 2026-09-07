/*
 * Copyright 2026 Google LLC
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.google.common.collect.ImmutableList;
import java.net.URI;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class IdentityServerDescriptorProviderTest {

  @Test
  public void testAllowedIssuer_varargs() {
    IdentityServerDescriptorProvider provider =
        new IdentityServerDescriptorProvider("https://accounts.google.com", "https://example.com");

    assertEquals(
        URI.create("https://accounts.google.com"),
        provider.getServerDescriptor("https://accounts.google.com"));
    assertEquals(
        URI.create("https://example.com"),
        provider.getServerDescriptor("https://example.com"));
  }

  @Test
  public void testAllowedIssuer_collection() {
    IdentityServerDescriptorProvider provider =
        new IdentityServerDescriptorProvider(
            ImmutableList.of("https://accounts.google.com", "https://example.com"));

    assertEquals(
        URI.create("https://accounts.google.com"),
        provider.getServerDescriptor("https://accounts.google.com"));
  }

  @Test
  public void testDisallowedIssuer_returnsNull() {
    IdentityServerDescriptorProvider provider =
        new IdentityServerDescriptorProvider("https://accounts.google.com");

    assertNull(provider.getServerDescriptor("https://attacker.com"));
    assertNull(provider.getServerDescriptor("http://169.254.169.254/latest/meta-data/"));
  }

  @Test
  public void testNullOrEmptyIssuer_returnsNull() {
    IdentityServerDescriptorProvider provider =
        new IdentityServerDescriptorProvider("https://accounts.google.com");

    assertNull(provider.getServerDescriptor(null));
    assertNull(provider.getServerDescriptor(""));
  }
}
