package net.trajano.websphere.internal;

import static java.util.Collections.emptyList;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import com.ibm.websphere.security.CertificateMapFailedException;
import com.ibm.websphere.security.CertificateMapNotSupportedException;
import com.ibm.websphere.security.CustomRegistryException;
import com.ibm.websphere.security.EntryNotFoundException;
import com.ibm.websphere.security.NotImplementedException;
import com.ibm.websphere.security.PasswordCheckFailedException;
import com.ibm.websphere.security.Result;
import com.ibm.websphere.security.UserRegistry;
import com.ibm.websphere.security.cred.WSCredential;

public class NoopUserRegistry implements
    UserRegistry {

    /**
     * Requested groups for the thread. This gets populated on invocations of
     * {@link #isValidGroup(String)}.
     */
    private final ThreadLocal<Set<String>> groupsTL = new ThreadLocal<Set<String>>() {

        /**
         * {@inheritDoc}
         */
        @Override
        protected Set<String> initialValue() {

            return new HashSet<>();
        }
    };

    @Override
    public String checkPassword(final String userSecurityName,
        final String password)
            throws PasswordCheckFailedException,
            CustomRegistryException,
            RemoteException {

        return userSecurityName;
    }

    @Override
    public WSCredential createCredential(final String userSecurityName)
        throws NotImplementedException,
        EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return null;
    }

    private Result emptyResult() {

        final Result result = new Result();
        result.setList(emptyList());
        return result;
    }

    @Override
    public String getGroupDisplayName(final String groupSecurityName)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return groupSecurityName;
    }

    @Override
    public Result getGroups(final String pattern,
        final int limit) throws CustomRegistryException,
            RemoteException {

        return emptyResult();
    }

    @Override
    public String getGroupSecurityName(final String uniqueGroupId)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return uniqueGroupId;
    }

    @Override
    public List<String> getGroupsForUser(final String groupSecurityName)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return emptyList();
    }

    @Override
    public String getRealm() throws CustomRegistryException,
        RemoteException {

        return "customRealm"; // documentation says can be null, but should
                              // really be non-null!
    }

    @Override
    public String getUniqueGroupId(final String groupSecurityName)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return groupSecurityName;
    }

    @Override
    public List<String> getUniqueGroupIds(final String uniqueUserId)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return new ArrayList<>(groupsTL.get());
    }

    @Override
    public String getUniqueUserId(final String userSecurityName)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return userSecurityName;
    }

    @Override
    public String getUserDisplayName(final String userSecurityName)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return userSecurityName;
    }

    @Override
    public Result getUsers(final String pattern,
        final int limit) throws CustomRegistryException,
            RemoteException {

        return emptyResult();
    }

    @Override
    public String getUserSecurityName(final String uniqueUserId)
        throws EntryNotFoundException,
        CustomRegistryException,
        RemoteException {

        return uniqueUserId;
    }

    @Override
    public Result getUsersForGroup(final String paramString,
        final int paramInt)
            throws NotImplementedException,
            EntryNotFoundException,
            CustomRegistryException,
            RemoteException {

        return emptyResult();
    }

    @Override
    public void initialize(final Properties props) throws CustomRegistryException,
        RemoteException {

    }

    @Override
    public boolean isValidGroup(final String groupSecurityName) throws CustomRegistryException,
        RemoteException {

        groupsTL.get().add(groupSecurityName);
        return true;
    }

    @Override
    public boolean isValidUser(final String userSecurityName) throws CustomRegistryException,
        RemoteException {

        return true;
    }

    @Override
    public String mapCertificate(final X509Certificate[] certs) throws CertificateMapNotSupportedException,
        CertificateMapFailedException,
        CustomRegistryException,
        RemoteException {

        try {
            for (final X509Certificate cert : certs) {
                for (final Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                    if (rdn.getType().equalsIgnoreCase("CN")) {
                        return rdn.getValue().toString();
                    }
                }
            }
        } catch (final InvalidNameException e) {
        }

        throw new CertificateMapFailedException("No valid CN in any certificate");
    }

}
