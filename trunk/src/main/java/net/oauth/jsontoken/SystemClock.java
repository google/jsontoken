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

public class SystemClock implements Clock {

  public static final Duration DEFAULT_ACCEPTABLE_CLOCK_SKEW = Duration.standardMinutes(2);

  private final Duration acceptableClockSkew;

  public SystemClock() {
    this(DEFAULT_ACCEPTABLE_CLOCK_SKEW);
  }

  public SystemClock(Duration acceptableClockSkew) {
    this.acceptableClockSkew = acceptableClockSkew;
  }

  @Override
  public Instant now() {
    return new Instant();
  }

  @Override
  public boolean isCurrentTimeInInterval(Instant start, Duration intervalLength) {
    Interval interval = new Interval(start, intervalLength);
    Instant now = now();
    Interval currentTimeWithSkew =
        new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
    return interval.overlaps(currentTimeWithSkew);
  }
}
