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
package net.oauth.jsontoken;

import java.time.Instant;

/** Clock interface. */
public interface Clock {

  /** Returns current time. */
  Instant now();

  /**
   * Determines whether the current time falls within the interval defined by {@code start} and
   * {@code end}. Implementations are free to fudge this a little bit to take into account possible
   * clock skew.
   */
  boolean isCurrentTimeInInterval(Instant start, Instant end);
}
