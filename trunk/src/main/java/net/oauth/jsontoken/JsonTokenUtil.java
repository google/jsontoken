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

import com.google.gson.Gson;
import com.google.gson.JsonObject;


/**
 * Some utility functions for {@link JsonToken}s.
 */
class JsonTokenUtil {

  static public final String DELIMITER = ".";

  public static String toBase64(JsonObject json) {
    return jsonToBase64(toJson(json));
  }

  public static String toJson(JsonObject json) {
    return new Gson().toJson(json);
  }

  private static String jsonToBase64(String source) {
    return Base64.encodeBase64URLSafeString(StringUtils.getBytesUtf8(source));
  }

  private JsonTokenUtil() { }
}
