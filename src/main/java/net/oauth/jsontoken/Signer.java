package net.oauth.jsontoken;


public interface Signer {

    byte[] sign(byte[] source);

}
