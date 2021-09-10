/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.custom.authenticator.samlsso.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.custom.authenticator.samlsso.CustomOpenIDConnectAuthenticator;
import org.wso2.carbon.identity.custom.authenticator.samlsso.CustomSAMLSSOAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.FileInputStream;

@Component(
        name = "identity.custom.application.authenticator.sso.component",
        immediate = true)
public class CustomSSOAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomSSOAuthenticatorServiceComponent.class);

    private static String postPage = null;

    @Activate
    protected void activate(ComponentContext ctxt) {
        FileInputStream fis = null;
        try {
            CustomSAMLSSOAuthenticator customSAMLSSOAuthenticator = new CustomSAMLSSOAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    customSAMLSSOAuthenticator, null);
            CustomOpenIDConnectAuthenticator customOpenIDConnectAuthenticator = new CustomOpenIDConnectAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    customOpenIDConnectAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.info("Custom SSO Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed Custom SSO bundle activation" + e);
            }
        } finally {
            IdentityIOStreamUtils.closeInputStream(fis);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.info("SAML2 SSO Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the SAML2 SSO Authenticator bundle");
        }
        CustomSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the SAML2 SSO Authenticator bundle");
        }
        CustomSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "ServerConfigurationService",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService")
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {
        if (log.isDebugEnabled()) {
            log.debug("Set the ServerConfiguration Service");
        }
        CustomSSOAuthenticatorServiceDataHolder.getInstance().setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {
        if (log.isDebugEnabled()) {
            log.debug("Unset the ServerConfiguration Service");
        }
        CustomSSOAuthenticatorServiceDataHolder.getInstance().setServerConfigurationService(null);
    }
}

