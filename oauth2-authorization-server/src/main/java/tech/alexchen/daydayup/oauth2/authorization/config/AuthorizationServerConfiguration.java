package tech.alexchen.daydayup.oauth2.authorization.config;

import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import tech.alexchen.daydayup.oauth2.authorization.custom.password.OAuth2UsernamePasswordAuthenticationConverter;
import tech.alexchen.daydayup.oauth2.authorization.custom.password.OAuth2UsernamePasswordAuthenticationProvider;
import tech.alexchen.daydayup.oauth2.authorization.custom.provider.CustomAuthenticationProvider;
import tech.alexchen.daydayup.oauth2.authorization.custom.token.UUIDOAuth2AccessTokenGenerator;
import tech.alexchen.daydayup.oauth2.authorization.custom.token.UUIDOAuth2RefreshTokenGenerator;

import java.util.Arrays;

/**
 * @author alexchen
 */
@Configuration
public class AuthorizationServerConfiguration {

    @Resource
    OAuth2TokenGenerator<?> oAuth2TokenGenerator;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
                .authorizationServerSettings(
                        // 指明为 localhost，就不会自动配置为本机的内网 ip，防止 client 和 resource 因为端点不一致导致的错误
                        AuthorizationServerSettings.builder()
                                .issuer("http://localhost:9000")
                                .build()
                )
                .tokenEndpoint((tokenEndpoint) -> tokenEndpoint.accessTokenRequestConverter(accessTokenRequestConverter()))
        ;
        http.exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        // 不加支持 TEXT_HTML，访问 login 页面会 401
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );
        http.csrf(AbstractHttpConfigurer::disable);
        // 先 build，后面才可以通过 http.getSharedObject 方法获取到 AuthenticationManager
        DefaultSecurityFilterChain securityFilterChain = http.build();

        addCustomOAuth2GrantAuthenticationProvider(http);
        return securityFilterChain;
    }

    public AuthenticationConverter accessTokenRequestConverter() {
        return new DelegatingAuthenticationConverter(Arrays.asList(
                new OAuth2UsernamePasswordAuthenticationConverter(),
                new OAuth2RefreshTokenAuthenticationConverter(),
                new OAuth2ClientCredentialsAuthenticationConverter(),
                new OAuth2AuthorizationCodeAuthenticationConverter(),
                new OAuth2AuthorizationCodeRequestAuthenticationConverter()));
    }

    public void addCustomOAuth2GrantAuthenticationProvider(HttpSecurity http) {
        // 添加 oauth2 的密码模式，处理 OAuth2UsernamePasswordAuthenticationToken
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);

        OAuth2UsernamePasswordAuthenticationProvider customProvider = new OAuth2UsernamePasswordAuthenticationProvider(
                authorizationService, oAuth2TokenGenerator, authenticationManager);
        http.authenticationProvider(customProvider);
    }

}
