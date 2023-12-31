package tech.alexchen.daydayup.oauth2.authorization.custom.token;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.util.UUID;

public class UUIDKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}
