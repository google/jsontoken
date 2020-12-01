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

import com.google.common.collect.Maps;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.security.PublicKey;
import java.util.Map;
import net.oauth.jsontoken.crypto.MagicRsaPublicKey;

/**
 * Implementation of the {@link ServerInfo} interface that assumes the server info document is in
 * JSON format. It can parse such a JSON-formatted server info document and exposes its contents
 * through the requisite methods of the {@link ServerInfo} interface.
 */
public class JsonServerInfo implements ServerInfo {

  @SerializedName("verification_keys")
  private final Map<String, String> verificationKeys = Maps.newHashMap();

  /**
   * Parses a JSON-formatted server info document and returns it as a {@link JsonServerInfo} object.
   *
   * @param json the contents of the JSON-formatted server info document.
   */
  public static JsonServerInfo getDocument(String json) {
    return new Gson().fromJson(json, JsonServerInfo.class);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.discovery.ServerInfo#getVerificationKey(java.lang.String)
   */
  @Override
  public PublicKey getVerificationKey(String keyId) {
    String magicKey = verificationKeys.get(keyId);
    if (magicKey == null) {
      return null;
    } else {
      return new MagicRsaPublicKey(magicKey).getKey();
    }
  }
}
