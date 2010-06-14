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

import com.google.gson.annotations.SerializedName;

import net.oauth.jsontoken.DefaultPayloadImpl;

public class SignedOAuthTokenPayload extends DefaultPayloadImpl {

  @SerializedName("uri")
  private String uri;

  @SerializedName("method")
  private String method;

  @SerializedName("body_hash")
  private String bodyHash;

  @SerializedName("token")
  private String token;

  @SerializedName("nonce")
  private String nonce;

  public String getUri() {
    return uri;
  }

  public void setUri(String uri) {
    this.uri = uri;
  }

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public String getBodyHash() {
    return bodyHash;
  }

  public void setBodyHash(String bodyHash) {
    this.bodyHash = bodyHash;
  }

  public String getOAuthToken() {
    return token;
  }

  public void setOAuthToken(String token) {
    this.token = token;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }
}