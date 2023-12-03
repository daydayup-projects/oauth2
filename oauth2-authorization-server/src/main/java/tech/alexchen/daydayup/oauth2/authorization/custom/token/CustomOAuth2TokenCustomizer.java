package tech.alexchen.daydayup.oauth2.authorization.custom.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * token 信息增强
 */
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    private static final Log logger = LogFactory.getLog(CustomOAuth2TokenCustomizer.class);

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        logger.trace("Invoking CustomOAuth2TokenCustomizer");
        OAuth2TokenClaimsSet.Builder claims = context.getClaims();
        String clientId = context.getAuthorizationGrant().getName();
        claims.claim("clientId", clientId);
        claims.claim("active", Boolean.TRUE);
        claims.claim("test-token-claim", "this is a test token claim");

        if ("client_credentials".equals(context.getAuthorizationGrantType().getValue())) {
            return;
        }
        User user = (User) context.getPrincipal().getPrincipal();
        claims.claim("username", user.getUsername());
    }
}
