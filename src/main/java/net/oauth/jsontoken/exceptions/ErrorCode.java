package net.oauth.jsontoken.exceptions;

public enum ErrorCode {

 /**
  * The header is missing required parameters.
  */
 BAD_HEADER,

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
  * Token string is corrupted and/or does not contain three components.
  */
 MALFORMED_TOKEN_STRING,

 /**
  * There are no verifiers available for a given issuer.
  */
 NO_VERIFIER,

 /**
  * Generic catch-all for exceptions with scenarios that are not pre-defined.
  */
 UNKNOWN,

 /**
  * The signature algorithm is not supported or is unknown.
  */
 UNSUPPORTED_ALGORITHM

}

