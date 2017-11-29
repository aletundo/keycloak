package org.keycloak.credential.hash;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MediaWikiBTypePasswordHashProviderFactory implements PasswordHashProviderFactory {
    
    public static final String ID = "mediawiki-B-type";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new MediaWikiBTypePasswordHashProvider(ID);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }
}
