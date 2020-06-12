package net.oauth.jsontoken;

import com.google.gson.JsonObject;

import java.security.SignatureException;

/**
 * Fails on any audience (even null).
 */
public class AlwaysFailAudience implements Checker {

  @Override
  public void check(JsonObject payload) throws SignatureException {
    throw new SignatureException();
  }

}
