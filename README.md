# customFederatedAuthenticator

The purpose of this custom federated authenticator is to define the authenticated user store domain and subject claim when the user store is shared between the APIM 3. x.x and the external Identity provider

Steps to apply the federated authenticator.

1.Build the java project and place the .jar file  <APIM_HOME>/repository/components/dropins folder (In distributed setup apply the jar in both publisher and store node)

2.Then add the following configuration to the deployment.toml file resides in <APIM_HOME>/repository/conf folder (In distributed setup apply the jar in both publisher and store node). for "user_store_domain" property please configure your secondary user store domain name. And for the "subject_claim" property, please configure the subject claim in the authentication response received from the IDP.

[[authentication.custom_authenticator]]

name = "CustomOpenIDConnectAuthenticator"  
alias = "customoicdsso"

[authentication.custom_authenticator.parameters]

user_store_domain = "ADS" 

subject_claim = "prefferd_username"

3.Restart the server.

4.Then login to management console and go to Home-> Identity Providers -> List -> Select the IDP configured -> expand the "Federated Authenticators" section. Then you will observe the new custom OIDC authenticator "Custom OpenID SSO Configuration". Expand the '"Custom OpenID SSO Configuration"'. Select checkbox "enable". And then configure the external IDP endpoints
