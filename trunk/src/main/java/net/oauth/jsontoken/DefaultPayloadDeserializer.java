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

import com.google.gson.Gson;

/**
 * Class that knows how to deserialize a JSON object. It uses the standard Gson
 * deserializer, i.e., doesn't use any custom type handlers.
 *
 * @param <T> The type of the class that will fall out of the deserialization process.
 */
public class DefaultPayloadDeserializer<T extends Payload> implements PayloadDeserializer<T> {

  /**
   * Creates a new deserializer for a certain class.
   * @param <T> type of the class to deserialize.
   * @param clazz class object of the deserializable class.
   * @return the deserializer.
   */
  public static <T extends Payload> DefaultPayloadDeserializer<T> newDeserializer(Class<T> clazz) {
    return new DefaultPayloadDeserializer<T>(clazz);
  }

  private final Class<T> clazz;

  private DefaultPayloadDeserializer(Class<T> clazz) {
    this.clazz = clazz;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.PayloadDeserializer#fromJson(java.lang.String)
   */
  @Override
  public T fromJson(String json) {
    return new Gson().fromJson(json, clazz);
  }
}
