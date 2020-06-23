package net.oauth.jsontoken.exceptions;

public enum ErrorCode {
 /**
  * Signature failed verification.
  */
 BAD_SIGNATURE,

 /**
  * IAT is after EXP or IAT is in the future
  */
 BAD_TIME_RANGE,

 /**
  * IAT and EXP are both in the past.
  */
 EXPIRED_TOKEN,

 /**
  * Something went wrong internally.
  */
 INTERNAL_ERROR,

 /**
  * Token string is corrupted and/or does not contain three components.
  */
 MALFORMED_TOKEN_STRING,

 /**
  * There are no verifiers available for a given issuer.
  */
 NO_VERIFIER,

 /**
  * Generic catch-all for unknown and ambiguous exceptions.
  */
 UNKNOWN,

 /**
  * The signature algorithm is not supported or is unknown.
  */
 UNSUPPORTED_ALGORITHM

}

