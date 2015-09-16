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
import com.ibm.websphere.security.NotImplementedException;
import com.ibm.websphere.security.Result;
import com.ibm.websphere.security.UserRegistry;
import com.ibm.websphere.security.cred.WSCredential;

public class NoopUserRegistry implements
    UserRegistry {

    /**
     * Requested groups for the thread. This gets populated on invocations of
     * {@link #isValidGroup(String)}.
     */
    private final ThreadLocal<Set<String>> groupsTL;

    /**
     * Initialize the groups {@link ThreadLocal}.
     */
    public NoopUserRegistry() {
        groupsTL = new ThreadLocal<Set<String>>() {

            /**
             * @return mutable empty {@link java.util.HashSet}
             */
            @Override
            protected Set<String> initialValue() {

                return new HashSet<>();
            }
        };
    }

    @Override
    public String checkPassword(final String userSecurityName,
        final String password) {

        return userSecurityName;
    }

    @Override
    public WSCredential createCredential(final String userSecurityName) {

        return null;
    }

    private Result emptyResult() {

        final Result result = new Result();
        result.setList(emptyList());
        return result;
    }

    @Override
    public String getGroupDisplayName(final String groupSecurityName) {

        return groupSecurityName;
    }

    @Override
    public Result getGroups(final String pattern,
        final int limit) {

        return emptyResult();
    }

    @Override
    public String getGroupSecurityName(final String uniqueGroupId) {

        return uniqueGroupId;
    }

    /**
     * {@inheritDoc} The contents of the collected group names are returned in
     * {@link List} form. This is provided for completeness, but is not used
     * during the JASPIC authentication process.
     *
     * @return groups set as a {@link List}
     */
    @Override
    public List<String> getGroupsForUser(final String userSecurityName) {

        return new ArrayList<>(groupsTL.get());
    }

    @Override
    public String getRealm() {

        return "customRealm"; // documentation says can be null, but should
                              // really be non-null!
    }

    @Override
    public String getUniqueGroupId(final String groupSecurityName) {

        return groupSecurityName;
    }

    /**
     * {@inheritDoc} The contents of the collected group names are returned in
     * {@link List} form.
     *
     * @return groups set as a {@link List}
     */
    @Override
    public List<String> getUniqueGroupIds(final String uniqueUserId) {

        return new ArrayList<>(groupsTL.get());
    }

    @Override
    public String getUniqueUserId(final String userSecurityName) {

        return userSecurityName;
    }

    @Override
    public String getUserDisplayName(final String userSecurityName) {

        return userSecurityName;
    }

    @Override
    public Result getUsers(final String pattern,
        final int limit) {

        return emptyResult();
    }

    @Override
    public String getUserSecurityName(final String uniqueUserId) {

        return uniqueUserId;
    }

    /**
     * {@inheritDoc}. Throws {@link NotImplementedException}.
     */
    @Override
    public Result getUsersForGroup(final String paramString,
        final int paramInt)
            throws NotImplementedException {

        throw new NotImplementedException();
    }

    /**
     * {@inheritDoc}. Originally this was meant to initialize the thread local,
     * but this method is no longer called as of WLP 8.5.5.7.
     */
    @Override
    public void initialize(final Properties props) {

    }

    /**
     * {@inheritDoc} Adds the group name to the groups {@link ThreadLocal}.
     *
     * @return <code>true</code>
     */
    @Override
    public boolean isValidGroup(final String groupSecurityName) {

        groupsTL.get().add(groupSecurityName);
        return true;
    }

    @Override
    public boolean isValidUser(final String userSecurityName) {

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
