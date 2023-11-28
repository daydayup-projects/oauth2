package tech.alexchen.daydayup.oauth2.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

/**
 * @author alexchen
 */
@Configuration
public class ResourceServerConfiguration {

    private static final String AUTHORIZATION_URI = "http://auth-server:9000/oauth2/authorize";
    private static final String TOKEN_URI = "http://auth-server:9000/oauth2/token";
    private static final String REDIRECT_URI = "http://auth-client:8080/login/oauth2/code/zeus";
    private static final String USER_INFO_URI = "http://auth-server:9000/userinfo";

    private static final String ZEUS_CLIENT_ID = "zeus";
    private static final String ZEUS_CLIENT_SECRET = "zeus";

    /**
     * 注册 client
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration zeusClient = ClientRegistration
                .withRegistrationId(ZEUS_CLIENT_ID)
                .clientId(ZEUS_CLIENT_ID)
                .clientSecret(ZEUS_CLIENT_SECRET)
                .clientName(ZEUS_CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .authorizationUri(AUTHORIZATION_URI)
                .tokenUri(TOKEN_URI)
                .userInfoUri(USER_INFO_URI)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .scope(OidcScopes.OPENID, "all")
                .build();
        return new InMemoryClientRegistrationRepository(zeusClient);
    }
}
