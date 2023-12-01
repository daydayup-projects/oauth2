package tech.alexchen.daydayup.oauth2.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/")
    public String index() {
        return "Login success!";
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_user.read')")
    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal Jwt jwt) {
        return "hello, " + jwt.getSubject();
    }
}
