/**
 * 
 */
package net.cowism.storage.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomUserStorageProvider implements UserStorageProvider, 
  UserLookupProvider, 
  CredentialInputValidator,
  UserQueryProvider {
    
    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        log.info("[I35] getUserById({})",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(sid.getExternalId(),realm);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        log.info("[I41] getUserByUsername({})",username);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users where username = ?");
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
        log.info("[I48] getUserByEmail({})",email);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, firstName,lastName, email, birthDate from users where email = ?");
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
        log.info("[I57] supportsCredentialType({})",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("[I57] isValid(realm={},user={},credentialInput.type={})",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }

        log.info("[I59] Password checking is not implemented yet");
        return false; // credential checking isn't available yet
        /*StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select password from users where username = ?");
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                String pwd = rs.getString(1);
                return pwd.equals(credentialInput.getChallengeResponse());
            }
            else {
                return false;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }*/
    }

    // UserQueryProvider implementation
    
    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("[I93] getUsersCount: realm={}", realm.getName() );
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
        log.info("[I113] getUsers: realm={}", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) order by UserName offset ? rows fetch next ? rows only");
            st.setInt(1, maxResults);
            st.setInt(2, firstResult);
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
        log.info("[I139] searchForUser: realm={}", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select FirstName=RTRIM(ISNULL(FIRST_NAME,SUBSTRING(A.OPRDEFNDESC,0,CHARINDEX(' ',A.OPRDEFNDESC)))), LastName=LTRIM(ISNULL(LAST_NAME,SUBSTRING(A.OPRDEFNDESC,CHARINDEX(' ',A.OPRDEFNDESC),LEN(A.OPRDEFNDESC)))), UserName=A.OPRID, Email=A.EMAILID, AcctLocked=A.ACCTLOCK from PSOPRDEFN A left outer join PS_NAMES B on A.EMPLID = B.EMPLID where ISNUMERIC(A.OPRID) = 1 and (B.EFFDT IS NULL or B.EFFDT = (select MAX(EFFDT) from PS_NAMES Z where Z.EMPLID = B.EMPLID)) and UserName like ? order by UserName offset ? rows fetch next ? rows only");
            st.setString(1, search);
            st.setInt(2, maxResults);
            st.setInt(3, firstResult);
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
        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("UserName"))
          .email(rs.getString("Email"))
          .firstName(rs.getString("FirstName"))
          .lastName(rs.getString("LastName"))
          .acctLocked(rs.getBoolean("AcctLocked"))
          .build();
        
        return user;
    }
}
