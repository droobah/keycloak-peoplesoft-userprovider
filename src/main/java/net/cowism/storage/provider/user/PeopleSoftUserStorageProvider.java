package net.cowism.storage.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.jboss.logging.Logger;

import static net.cowism.storage.provider.user.PeopleSoftUserStorageProviderConstants.*;

public class PeopleSoftUserStorageProvider implements UserStorageProvider,
  UserLookupProvider, 
  CredentialInputValidator,
  UserQueryProvider {
    
    private static final Logger log = Logger.getLogger(PeopleSoftUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;

    public PeopleSoftUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        log.infof("[I35] getUserById(%s)",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(sid.getExternalId(),realm);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        log.infof("[I41] getUserByUsername(%s)",username);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) and A.OPRID = ?");
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        log.infof("[I48] getUserByEmail(%s)",email);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) and A.EMAILID  = ?");
            st.setString(1, email);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.infof("[I57] supportsCredentialType(%s)",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.infof("[I57] isConfiguredFor(realm=%s,user=%s,credentialType=%s)",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.infof("[I57] isValid(realm=%s,user=%s,credentialInput.type=%s)",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }

        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();
        String password = credentialInput.getChallengeResponse();

        try {
            //allow self-signed certificates
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new java.security.SecureRandom());

            //setup authentication
            HttpAuthenticationFeature authentication = HttpAuthenticationFeature.universalBuilder()
                    .credentialsForBasic(username, password)
                    .credentials(username, password).build();

            //send request from config to get XML result
            Client client = ClientBuilder.newBuilder()
                                        .sslContext(sslcontext)
                                        .hostnameVerifier((s1, s2) -> true)
                                        .build();
            String response
                            = client.register(authentication)
                            .target(this.model.get(CONFIG_KEY_PEOPLESOFT_URL))
                            .path(username)
                            .request(MediaType.APPLICATION_XML)
                            .get(String.class);

            //check for fault and sanity
            if (response.contains("CIFault")) {
                //error retrieving information, user must be unauthorized
                log.warn("[W98] CIFault from PeopleSoft REST call");
                throw new RuntimeException("CIFault Response:" + response);
            }
            if (response.contains("<UserID>"+username+"</UserID>")) {
                log.infof("[I99] PeopleSoft login successful for %s", username);
                return true;
            }

            log.infof("[I98] Unknown PeopleSoft authentication failure with XML object: %s",response);
            return false;
        }
        catch (NotAuthorizedException ex) {
            log.warnf("[W99] PeopleSoft authentication failure for user %s",username);
            return false;
        }
        catch (Exception ex) {
            throw new RuntimeException("Unknown REST Error:" + ex.getMessage(),ex);
        }
    }

    // UserQueryProvider implementation
    
    @Override
    public int getUsersCount(RealmModel realm) {
        log.infof("[I93] getUsersCount: realm=%s", realm.getName() );
        try ( Connection c = DbUtil.getConnection(this.model)) {
            Statement st = c.createStatement();
            st.execute("select count(*) from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) order by UserName");
            ResultSet rs = st.getResultSet();
            rs.next();
            return rs.getInt(1);
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return getUsers(realm,0, 5000); // Keep a reasonable maxResults 
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        log.infof("[I113] getUsers: realm=%s", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) order by UserName offset ? rows fetch next ? rows only");
            st.setInt(1, firstResult);
            st.setInt(2, maxResults);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users;
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search,realm,0,5000);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        log.infof("[I139] searchForUser: realm=%s", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) and A.OPRID like ? order by UserName offset ? rows fetch next ? rows only");
            st.setString(1, search);
            st.setInt(2, firstResult);
            st.setInt(3, maxResults);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users;
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return searchForUser(params,realm,0,5000);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        return getUsers(realm, firstResult, maxResults);
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        return Collections.emptyList();
    }

    
    //------------------- Implementation 
    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
        PeopleSoftUser user = new PeopleSoftUser.Builder(ksession, realm, model, rs.getString("UserName"))
          .email(rs.getString("Email"))
          .firstName(rs.getString("FirstName"))
          .lastName(rs.getString("LastName"))
          .acctLocked(rs.getBoolean("AcctLocked"))
          .build();
        
        return user;
    }
}
