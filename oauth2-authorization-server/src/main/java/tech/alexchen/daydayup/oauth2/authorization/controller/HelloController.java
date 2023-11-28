package tech.alexchen.daydayup.oauth2.authorization.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author alexchen
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public Object hello() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
