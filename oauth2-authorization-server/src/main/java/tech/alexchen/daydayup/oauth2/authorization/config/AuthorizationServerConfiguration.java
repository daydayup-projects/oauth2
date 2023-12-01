package tech.alexchen.daydayup.oauth2.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author alexchen
 */
@Configuration
public class AuthorizationServerConfiguration {

//        @Bean
//        @Order(1)
//        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//            OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//            return http.formLogin(Customizer.withDefaults()).build();
//        }
//
//        @Bean
//        @Order(2)
//        public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
//            http
//                    .authorizeHttpRequests((authorize) -> authorize
//                            .anyRequest().authenticated()
//                    )
//                    .formLogin(Customizer.withDefaults());
//            return http.build();
//        }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("123456")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

//        @Bean
//        public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
//            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//            RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                    .privateKey(privateKey)
//                    .keyID(UUID.randomUUID().toString())
//                    .build();
//            JWKSet jwkSet = new JWKSet(rsaKey);
//            return new ImmutableJWKSet<>(jwkSet);
//        }
//
//        @Bean
//        public JwtDecoder jwtDecoder(KeyPair keyPair) {
//            return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
//        }
//

//
//        @Bean
//        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
//        KeyPair generateRsaKey() {
//            KeyPair keyPair;
//            try {
//                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//                keyPairGenerator.initialize(2048);
//                keyPair = keyPairGenerator.generateKeyPair();
//            }
//            catch (Exception ex) {
//                throw new IllegalStateException(ex);
//            }
//            return keyPair;
//        }
//
//    @Bean
//    public AuthorizationServerSettings providerSettings() {
//        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
//    }
}
