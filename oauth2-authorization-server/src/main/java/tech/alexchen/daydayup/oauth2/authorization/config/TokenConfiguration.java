package tech.alexchen.daydayup.oauth2.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import tech.alexchen.daydayup.oauth2.authorization.custom.token.CustomOAuth2TokenCustomizer;
import tech.alexchen.daydayup.oauth2.authorization.custom.token.UUIDOAuth2AccessTokenGenerator;
import tech.alexchen.daydayup.oauth2.authorization.custom.token.UUIDOAuth2RefreshTokenGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class TokenConfiguration {

    /**
     * 注入自定义的 opaqueToken 生成器，用于生成较短的 access_token 和 refresh_token
     */
    @Bean
    public OAuth2TokenGenerator<?> oAuth2TokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);

        UUIDOAuth2AccessTokenGenerator uuidOAuth2AccessTokenGenerator = new UUIDOAuth2AccessTokenGenerator();
        uuidOAuth2AccessTokenGenerator.setAccessTokenCustomizer(new CustomOAuth2TokenCustomizer());

        UUIDOAuth2RefreshTokenGenerator uuidOAuth2RefreshTokenGenerator = new UUIDOAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(uuidOAuth2AccessTokenGenerator, uuidOAuth2RefreshTokenGenerator, jwtGenerator);
    }

    /**
     * jwk 配置
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
