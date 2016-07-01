package org.wso2.rest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;

import org.ietf.jgss.GSSException;

import java.util.Map;


public class KerberosAuthHandler implements Handler {

    private static Log log = LogFactory.getLog(KerberosAuthHandler.class);

    public void addProperty(String s, Object o) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Map getProperties() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    public boolean handleRequest(MessageContext messageContext) {
        byte[] clientToken = null;
        byte[] serverToken = null;
        org.apache.axis2.context.MessageContext axis2MessageContext
                = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            if (headersMap.get("Authorization") == null) {
                return unAuthorizedUser(headersMap, axis2MessageContext, messageContext, null);
            } else {
                String authHeader = (String) headersMap.get("Authorization");
                if (authHeader != null) {
                    String negotiate = authHeader.substring(0, 10);
                    if ("Negotiate".equals(negotiate.trim())) {
                        KerberosAuthenticationUtil.init();
                        String authToken = authHeader.substring(10).trim();
                        clientToken = Base64.decodeBase64(authToken.getBytes());
                    }
                    KerberosAuthenticationUtil kerberosAuthenticationUtil = new KerberosAuthenticationUtil();
                    try {
                        serverToken = kerberosAuthenticationUtil.processToken(KerberosAuthenticationUtil.getKerberosCredentials(), clientToken);
                    } catch (GSSException e) {
                        log.error(e.getMessage(), e);
                    }
                    if (!kerberosAuthenticationUtil.getContextEstablised()) {
                        return unAuthorizedUser(headersMap, axis2MessageContext, messageContext, serverToken);
                    } else {
                        return authorized(axis2MessageContext);
                    }
                } else {
                    return accessForbidden(headersMap, axis2MessageContext, messageContext);
                }
            }
        }
        return true;
    }


    private boolean unAuthorizedUser(Map headersMap, org.apache.axis2.context.MessageContext axis2MessageContext,
                                     MessageContext messageContext, byte[] serverToken) {
        String outServerTokenString = null;
        headersMap.clear();
        try {
            if (serverToken != null) {
                byte[] outServerToken = Base64.encodeBase64(serverToken);
                outServerTokenString = new String(outServerToken, "UTF-8");
            }
            axis2MessageContext.setProperty("HTTP_SC", "401");
            if (outServerTokenString != null) {
                headersMap.put("WWW-Authenticate", "Negotiate " + outServerTokenString);
            } else {
                headersMap.put("WWW-Authenticate", "Negotiate");
            }
            axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
            messageContext.setProperty("RESPONSE", "true");
            messageContext.setTo(null);
            Axis2Sender.sendBack(messageContext);
            return false;

        } catch (Exception e) {
            return false;
        }
    }

    private boolean authorized(org.apache.axis2.context.MessageContext axis2MessageContext) {
        axis2MessageContext.setProperty("HTTP_SC", "200");
        return true;
    }

    private boolean accessForbidden(Map headersMap, org.apache.axis2.context.MessageContext axis2MessageContext,
                                    MessageContext messageContext) {
        headersMap.clear();
        axis2MessageContext.setProperty("HTTP_SC", "403");
        axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        Axis2Sender.sendBack(messageContext);
        return false;
    }


}
