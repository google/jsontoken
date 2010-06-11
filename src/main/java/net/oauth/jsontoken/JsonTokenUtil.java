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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

/**
 * Some utility functions for {@link JsonToken}s.
 */
class JsonTokenUtil {

  static public final String DELIMITER = ".";

  /**
   * Returns the base string for a given payload and envelope. Note that the
   * returned string is guaranteed to only contain ASCII characters, so can safely
   * be converted into a byte array of equal length.
   */
  static String getBaseString(Payload payload, Envelope envelope) {
    return getBaseString(jsonToBase64(payload.toJson()), jsonToBase64(envelope.toJson()));
  }

  /**
   * Returns the base string for a given serialized payload and envelope. Note that the
   * returned string is guaranteed to only contain ASCII characters, so can safely
   * be converted into a byte array of equal length.
   * @param payload The serialized payload. MUST only contain characters from the ASCII set.
   * @param envelope The serialized envelope. MUST only contain characters from the ASCII set.
   */
  static String getBaseString(String payload, String envelope) {
    return payload + DELIMITER + envelope + DELIMITER;
  }

  private static String jsonToBase64(String source) {
    return Base64.encodeBase64URLSafeString(StringUtils.getBytesUtf8(source));
  }

  private JsonTokenUtil() { }
}
