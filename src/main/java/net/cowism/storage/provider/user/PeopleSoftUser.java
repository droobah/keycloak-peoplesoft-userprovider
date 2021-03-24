package net.cowism.storage.provider.user;

import java.util.List;
import java.util.Map;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.AbstractUserAdapter;


class PeopleSoftUser extends AbstractUserAdapter {

    private final String username;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final Boolean acctLocked;

    private PeopleSoftUser(KeycloakSession session, RealmModel realm,
                           ComponentModel storageProviderModel,
                           String username,
                           String email,
                           String firstName,
                           String lastName,
                           Boolean acctLocked ) {
        super(session, realm, storageProviderModel);
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.acctLocked = acctLocked;

    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public String getEmail() {
        return email;
    }

    public Boolean getAcctLocked() {
        return acctLocked;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL,getEmail());
        attributes.add(UserModel.FIRST_NAME,getFirstName());
        attributes.add(UserModel.LAST_NAME,getLastName());
        attributes.add("acctLocked",getAcctLocked().toString());
        return attributes;
    }

    static class Builder {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final ComponentModel storageProviderModel;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private Boolean acctLocked;

        Builder(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel,String username) {
            this.session = session;
            this.realm = realm;
            this.storageProviderModel = storageProviderModel;
            this.username = username;
        }

        PeopleSoftUser.Builder email(String email) {
            this.email = email;
            return this;
        }

        PeopleSoftUser.Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        PeopleSoftUser.Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        PeopleSoftUser.Builder acctLocked(Boolean acctLocked) {
            this.acctLocked = acctLocked;
            return this;
        }

        PeopleSoftUser build() {
            return new PeopleSoftUser(
                    session,
                    realm,
                    storageProviderModel,
                    username,
                    email,
                    firstName,
                    lastName,
                    acctLocked);

        }
    }
}