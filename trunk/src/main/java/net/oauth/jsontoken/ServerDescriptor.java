package net.oauth.jsontoken;

import java.security.PublicKey;

public interface ServerDescriptor {

    public PublicKey getPublicKey(String keyIdentifier);

}
