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
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);
    private static final String USER_STORE_DOMAIN_ALIAS = "user_store_domain";
    private static final String SUBJECT_CLAIM = "subject_claim";


    @Override
    public String getName() {
        return "CustomOpenIDConnectAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "Custom OpenID SSO";
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        try {

            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);

            // Create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessTokenRequest);

            // TODO : return access token and id token to framework
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException(ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getCode(),
                        ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getMessage());
            }

            String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (StringUtils.isBlank(idToken) && requiredIDToken(authenticatorProperties)) {
                throw new AuthenticationFailedException(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getCode(),
                        String.format(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getMessage(),
                                getTokenEndpoint(authenticatorProperties),
                                authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID)));
            }

            OIDCStateInfo stateInfoOIDC = new OIDCStateInfo();
            stateInfoOIDC.setIdTokenHint(idToken);
            context.setStateInfo(stateInfoOIDC);

            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            AuthenticatedUser authenticatedUser;
            Map<ClaimMapping, String> claims = new HashMap<>();
            Map<String, Object> jsonObject = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                jsonObject = getIdTokenClaims(context, idToken);
                if (jsonObject == null) {
                    String errorMessage = ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getMessage();
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    throw new AuthenticationFailedException(ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getCode(),
                            errorMessage);
                }

                if (log.isDebugEnabled() && IdentityUtil
                        .isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
                    log.debug("Retrieved the User Information:" + jsonObject);
                }

                String authenticatedUserId = getAuthenticatedUserId(jsonObject);
                String attributeSeparator = OIDCAuthenticatorConstants.MULTI_ATTRIBUTE_SEPERATOR;

                for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                    buildClaimMappings(claims, entry, attributeSeparator);
                }
                authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("The IdToken is null");
                }
                authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                        getAuthenticateUser(context, jsonObject, oAuthResponse));
            }

            claims.putAll(getSubjectAttributes(oAuthResponse, authenticatorProperties));
            authenticatedUser.setUserAttributes(claims);

            context.setSubject(authenticatedUser);
            String userStoreDomain = getAuthenticatorConfig().getParameterMap().get(USER_STORE_DOMAIN_ALIAS);
            context.getSubject().setUserStoreDomain(userStoreDomain);
            context.getSubject().setFederatedUser(false);

        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException(ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getCode(),
                    ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getMessage(), context.getSubject(), e);
        }
    }
    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }
    private String  getAuthenticatedUserId( Map<String, Object>  jsonObject)
    {
        String subClaim=getAuthenticatorConfig().getParameterMap().get(SUBJECT_CLAIM);
        String email= jsonObject.get(subClaim).toString();
        return email;
    }
}
