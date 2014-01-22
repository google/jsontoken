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

import org.joda.time.Duration;
import org.joda.time.Instant;
import org.joda.time.Interval;

/**
 * Default implementation of {@link Clock}, which accepts clock skews (when comparing time
 * instances) of up to 2 minutes.
 */
public class SystemClock implements Clock {

  public static final Duration DEFAULT_ACCEPTABLE_CLOCK_SKEW = Duration.standardMinutes(2);

  private final Duration acceptableClockSkew;

  /**
   * Public constructor.
   */
  public SystemClock() {
    this(DEFAULT_ACCEPTABLE_CLOCK_SKEW);
  }

  /**
   * Public constructor.
   * @param acceptableClockSkew the current time will be considered inside the
   *   interval at {@link #isCurrentTimeInInterval(Instant, Duration)} even if the current time
   *   is up to acceptableClockSkew off the ends of the interval.
   */
  public SystemClock(Duration acceptableClockSkew) {
    this.acceptableClockSkew = acceptableClockSkew;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.Clock#now()
   */
  @Override
  public Instant now() {
    return new Instant();
  }

  /**
   * Determines whether the current time (plus minus the acceptableClockSkew) falls within the
   * interval defined by the start and intervalLength parameters.
   */
  @Override
  public boolean isCurrentTimeInInterval(Instant start, Instant end) {
    Interval interval = new Interval(start, end);
    Instant now = now();
    Interval currentTimeWithSkew =
        new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
    return interval.overlaps(currentTimeWithSkew);
  }
}
