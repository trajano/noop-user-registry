package net.trajano.websphere.internal;

import static java.util.Collections.emptyList;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;

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
    UserRegistry,
    BundleActivator,
    ManagedService {

    private final String CFG_PID = "noopUserRegistry";

    private ServiceRegistration<ManagedService> configRef = null;

    private ServiceRegistration<UserRegistry> curRef = null;

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

    /**
     * use this to set useful default values for user configuration, if desired
     */
    Dictionary<String, ?> getDefaults() {

        final Dictionary<String, String> defaults = new Hashtable<>();
        defaults.put(org.osgi.framework.Constants.SERVICE_PID, CFG_PID);
        return defaults;
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

        return new ArrayList<>(); // Apparently needs to be mutable
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

    /**
     * {@inheritDoc}
     */
    @Override
    public void start(final BundleContext context) throws Exception {

        configRef = context.registerService(
            ManagedService.class,
            this,
            getDefaults());
        curRef = context.registerService(
            UserRegistry.class,
            this,
            getDefaults());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop(final BundleContext context) throws Exception {

        if (configRef != null) {
            configRef.unregister();
            configRef = null;
        }
        if (curRef != null) {
            curRef.unregister();
            curRef = null;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updated(final Dictionary<String, ?> properties) throws ConfigurationException {

    }
}
