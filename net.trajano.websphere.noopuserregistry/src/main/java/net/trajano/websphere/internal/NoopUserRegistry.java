package net.trajano.websphere.internal;

import static java.util.Collections.emptyList;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

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

public class NoopUserRegistry implements UserRegistry {

	@Override
	public void initialize(Properties props) throws CustomRegistryException, RemoteException {
	}

	@Override
	public String checkPassword(String userSecurityName, String password)
			throws PasswordCheckFailedException, CustomRegistryException, RemoteException {
		return userSecurityName;
	}

	@Override
	public String mapCertificate(X509Certificate[] certs) throws CertificateMapNotSupportedException,
			CertificateMapFailedException, CustomRegistryException, RemoteException {
		try {
			for (X509Certificate cert : certs) {
				for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
					if (rdn.getType().equalsIgnoreCase("CN")) {
						return rdn.getValue().toString();
					}
				}
			}
		} catch (InvalidNameException e) {
		}

		throw new CertificateMapFailedException("No valid CN in any certificate");
	}

	@Override
	public String getRealm() throws CustomRegistryException, RemoteException {
		return "customRealm"; // documentation says can be null, but should
								// really be non-null!
	}

	@Override
	public Result getUsers(String pattern, int limit) throws CustomRegistryException, RemoteException {
		return emptyResult();
	}

	@Override
	public String getUserDisplayName(String userSecurityName)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return userSecurityName;
	}

	@Override
	public String getUniqueUserId(String userSecurityName)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return userSecurityName;
	}

	@Override
	public String getUserSecurityName(String uniqueUserId)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return uniqueUserId;
	}

	@Override
	public boolean isValidUser(String userSecurityName) throws CustomRegistryException, RemoteException {
		return true;
	}

	@Override
	public Result getGroups(String pattern, int limit) throws CustomRegistryException, RemoteException {
		return emptyResult();
	}

	@Override
	public String getGroupDisplayName(String groupSecurityName)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return groupSecurityName;
	}

	@Override
	public String getUniqueGroupId(String groupSecurityName)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return groupSecurityName;
	}

	@Override
	public List<String> getUniqueGroupIds(String uniqueUserId)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return new ArrayList<>(); // Apparently needs to be mutable
	}

	@Override
	public String getGroupSecurityName(String uniqueGroupId)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return uniqueGroupId;
	}

	@Override
	public boolean isValidGroup(String groupSecurityName) throws CustomRegistryException, RemoteException {
		return true;
	}

	@Override
	public List<String> getGroupsForUser(String groupSecurityName)
			throws EntryNotFoundException, CustomRegistryException, RemoteException {
		return emptyList();
	}

	@Override
	public Result getUsersForGroup(String paramString, int paramInt)
			throws NotImplementedException, EntryNotFoundException, CustomRegistryException, RemoteException {
		return emptyResult();
	}

	@Override
	public WSCredential createCredential(String userSecurityName)
			throws NotImplementedException, EntryNotFoundException, CustomRegistryException, RemoteException {
		return null;
	}

	private Result emptyResult() {
		Result result = new Result();
		result.setList(emptyList());
		return result;
	}
}
