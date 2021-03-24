package net.cowism.storage.provider.user;

import java.sql.Connection;
import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.jboss.logging.Logger;

import static net.cowism.storage.provider.user.PeopleSoftUserStorageProviderConstants.*;

public class PeopleSoftUserStorageProviderFactory implements UserStorageProviderFactory<PeopleSoftUserStorageProvider> {
    private static final Logger log = Logger.getLogger(PeopleSoftUserStorageProviderFactory.class);
    protected final List<ProviderConfigProperty> configMetadata;

    public PeopleSoftUserStorageProviderFactory() {
        log.info("[I24] PeopleSoftUserStorageProviderFactory created");


        // Create config metadata
        configMetadata = ProviderConfigurationBuilder.create()
                .property()
                    .name(CONFIG_KEY_JDBC_DRIVER)
                    .label("JDBC Driver Class")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue("com.microsoft.sqlserver.jdbc.SQLServerDriver")
                    .helpText("Fully qualified class name of the JDBC driver")
                    .add()
                .property()
                    .name(CONFIG_KEY_JDBC_URL)
                    .label("JDBC URL")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue("jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks")
                    .helpText("JDBC URL used to connect to the user database")
                    .add()
                .property()
                    .name(CONFIG_KEY_DB_USERNAME)
                    .label("Database User")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .helpText("Username used to connect to the database")
                    .add()
                .property()
                    .name(CONFIG_KEY_DB_PASSWORD)
                    .label("Database Password")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .helpText("Password used to connect to the database")
                    .secret(true)
                    .add()
                .property()
                    .name(CONFIG_KEY_VALIDATION_QUERY)
                    .label("SQL Validation Query")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .helpText("SQL query used to validate a connection")
                    .defaultValue("select 1")
                    .add()
                .property()
                    .name(CONFIG_KEY_PEOPLESOFT_URL)
                    .label("PeopleSoft REST API Url")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .helpText("Only designed for CIRT_USERMAINT_SELF_G_GET.V1 CI-REST webservice")
                    .defaultValue("https://psserver/PSIGW/RESTListeningConnector/PSFT_HR/CIRT_USERMAINT_SELF_G_GET.V1")
                    .add()
                .build();

    }

    @Override
    public PeopleSoftUserStorageProvider create(KeycloakSession ksession, ComponentModel model) {
        log.info("[I63] creating new PeopleSoftUserStorageProvider");
        return new PeopleSoftUserStorageProvider(ksession,model);
    }

    @Override
    public String getId() {
        log.info("[I69] getId()");
        return "peoplesoft-user-provider";
    }


    // Configuration support methods
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {

        try (Connection c = DbUtil.getConnection(config)) {
            log.info("[I84] Testing connection..." );
            c.createStatement().execute(config.get(CONFIG_KEY_VALIDATION_QUERY));
            log.info("[I92] Connection OK !" );
        }
        catch(Exception ex) {
            log.warnf("[W94] Unable to validate connection: ex=%s", ex.getMessage());
            throw new ComponentValidationException("Unable to validate database connection",ex);
        }
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        log.info("[I94] onUpdate()" );
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        log.info("[I99] onCreate()" );
    }
}
