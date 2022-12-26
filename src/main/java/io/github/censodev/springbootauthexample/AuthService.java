package io.github.censodev.springbootauthexample;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Collection;

public interface AuthService {

    @Getter
    @Builder
    class Tokens {
        private String accessToken;
        private String refreshToken;
    }

    Tokens login(String usn, String pwd);

    void signup(String usn, String pwd, Collection<User.RoleEnum> roles);
}
