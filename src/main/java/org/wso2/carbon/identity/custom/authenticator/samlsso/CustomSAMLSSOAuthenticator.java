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
package org.wso2.carbon.identity.custom.authenticator.samlsso;

import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAMLSSOAuthenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomSAMLSSOAuthenticator extends SAMLSSOAuthenticator implements FederatedApplicationAuthenticator {

    private static final String USER_STORE_DOMAIN_ALIAS = "user_store_domain";

    @Override
    public String getName() {
        return "CustomSAMLSSOAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "Custom SAML SSO";
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);
        String userStoreDomain = getAuthenticatorConfig().getParameterMap().get(USER_STORE_DOMAIN_ALIAS);
        context.getSubject().setUserStoreDomain(userStoreDomain);
        context.getSubject().setFederatedUser(false);
    }
}
