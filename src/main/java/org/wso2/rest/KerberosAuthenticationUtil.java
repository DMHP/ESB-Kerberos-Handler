package org.wso2.rest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.kerberos.KerberosPrincipal;

import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.util.Set;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;


public class KerberosAuthenticationUtil {
    private static Log log = LogFactory.getLog(KerberosAuthenticationUtil.class);
    static boolean isEstablished;
    static String spn;
    static String realm;
    static String keytab;
    private static transient GSSCredential localKerberosCredentials;
    private static GSSManager gssManager = GSSManager.getInstance();

    /**
     * Set jaas.conf and krb5 paths
     */
    public static void setConfigFilePaths() {
        Properties props = new Properties();
        try {
            props.load(new FileInputStream("./repository/conf/server.properties"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.auth.login.config", "./repository/conf/jaas.conf");
        spn = props.getProperty("principal");
        realm = props.getProperty("realm");
        keytab = props.getProperty("keyTab");
    }


    public static void init() {
        try {
            KerberosAuthenticationUtil.setConfigFilePaths();
            setKerberosCredentials(createCredentials());
        } catch (PrivilegedActionException | LoginException | GSSException e) {
            log.error(e.getMessage());
        }
    }

    public static Configuration getJaasKrb5TicketCfg(
            final String principal, final String realm, final File keytab) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<String, String>();
                options.put("principal", principal);
                options.put("realm", realm);
                options.put("keyTab", keytab.getAbsolutePath());
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("storeKey", "true");
                options.put("isInitiator", "false");

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                LoginModuleControlFlag.REQUIRED, options)
                };
            }
        };
    }

    private static GSSCredential createServerCredentials()
            throws PrivilegedActionException, LoginException, GSSException {
        Principal principal = new KerberosPrincipal(spn, KerberosPrincipal.KRB_NT_SRV_INST);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(principal);
        Subject subject = new Subject(false, principals, new HashSet<Object>(),
                new HashSet<Object>());
        LoginContext loginContext = new LoginContext("Server", subject, null, getJaasKrb5TicketCfg(spn, realm, new File(keytab)));
        try {
            loginContext.login();
        } catch (LoginException e) {
            log.error(e.getMessage());
        }
        return createCredentialsForSubject(loginContext.getSubject());
    }


    private static GSSCredential createCredentialsForSubject(final Subject subject) throws PrivilegedActionException, GSSException {
        final Oid mechOid = new Oid("1.3.6.1.5.5.2");
        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                                mechOid, GSSCredential.ACCEPT_ONLY);
                    }
                };

        return Subject.doAs(subject, action);
    }

    public static GSSCredential createCredentials()
            throws PrivilegedActionException, LoginException, GSSException {
        GSSCredential gssCredential = createServerCredentials();
        return gssCredential;
    }

    public static byte[] processToken(GSSCredential gssCredentials, byte[] gssToken) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSContext context = manager.createContext(gssCredentials);
        byte[] serverToken = context.acceptSecContext(gssToken, 0, gssToken.length);
        KerberosAuthenticationUtil kerberosAuthenticationUtil = new KerberosAuthenticationUtil();
        if (context.isEstablished()) {
            kerberosAuthenticationUtil.setContextEstablished(true);
        } else {
            kerberosAuthenticationUtil.setContextEstablished(false);
        }

        return serverToken;
    }


    private void setContextEstablished(boolean established) {
        isEstablished = established;
    }

    public boolean getContextEstablised() {
        return isEstablished;
    }

    private static void setKerberosCredentials(GSSCredential gssCredential) {
        localKerberosCredentials = gssCredential;
    }

    public static GSSCredential getKerberosCredentials() {
        return localKerberosCredentials;
    }

}
