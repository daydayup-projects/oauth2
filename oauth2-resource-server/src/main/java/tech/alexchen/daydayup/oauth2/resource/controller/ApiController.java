package tech.alexchen.daydayup.oauth2.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/")
    public String index() {
        return "Login success!";
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_read')")
    @GetMapping("/jwt")
    public Object hello(@AuthenticationPrincipal Jwt jwt) {
        return jwt;
    }

    @GetMapping("/opaque")
    public Object opaqueToken(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return principal;
    }
}
