package tech.alexchen.daydayup.oauth2.authorization.custom.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    private static final Log logger = LogFactory.getLog(CustomOAuth2TokenCustomizer.class);

    /**
     * Customize the OAuth 2.0 Token attributes.
     * @param context the context containing the OAuth 2.0 Token attributes
     */
    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        logger.trace("Invoking CustomOAuth2TokenCustomizer");
        OAuth2TokenClaimsSet.Builder claims = context.getClaims();
        String clientId = context.getAuthorizationGrant().getName();
        claims.claim("clientId", clientId);
        claims.claim("active", Boolean.TRUE);
        if ("client_credentials".equals(context.getAuthorizationGrantType().getValue())) {
            return;
        }
        User user = (User) context.getPrincipal().getPrincipal();
        claims.claim("username", user.getUsername());
    }
}
