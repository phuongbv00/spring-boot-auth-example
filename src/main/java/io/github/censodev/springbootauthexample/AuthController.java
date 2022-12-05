package io.github.censodev.springbootauthexample;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @GetMapping("profile")
    public User profile(Authentication authentication) {
        return (User) authentication.getCredentials();
    }

    @GetMapping("login")
    public AuthService.Tokens login(@RequestParam String usn,
                                    @RequestParam String pwd) {
        return authService.login(usn, pwd);
    }

    @GetMapping("signup")
    public void signup(@RequestParam String usn,
                       @RequestParam String pwd) {
        authService.signup(usn, pwd, null);
    }
}
