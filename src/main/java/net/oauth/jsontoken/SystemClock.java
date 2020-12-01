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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.Range;
import java.time.Duration;
import java.time.Instant;

/**
 * Default implementation of {@link Clock}, which accepts clock skews (when comparing time
 * instances) of up to 2 minutes.
 */
public class SystemClock implements Clock {

  public static final Duration DEFAULT_ACCEPTABLE_CLOCK_SKEW = Duration.ofMinutes(2);

  private final Duration acceptableClockSkew;

  /** Public constructor. */
  public SystemClock() {
    this(DEFAULT_ACCEPTABLE_CLOCK_SKEW);
  }

  /**
   * Public constructor.
   *
   * @param acceptableClockSkew the current time will be considered inside the interval at {@link
   *     #isCurrentTimeInInterval(Instant, Instant)} even if the current time is up to
   *     acceptableClockSkew off the ends of the interval.
   */
  public SystemClock(Duration acceptableClockSkew) {
    this.acceptableClockSkew = checkNotNull(acceptableClockSkew);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.Clock#now()
   */
  @Override
  public Instant now() {
    return Instant.now();
  }

  /**
   * Determines whether the current time (plus minus the {@code acceptableClockSkew}) falls within
   * the interval defined by {@code start} and {@code end}.
   */
  @Override
  public boolean isCurrentTimeInInterval(Instant start, Instant end) {
    Range<Instant> interval = Range.closed(start, end);
    Instant now = now();
    Range<Instant> currentTimeWithSkew =
        Range.closed(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
    return interval.isConnected(currentTimeWithSkew);
  }
}
