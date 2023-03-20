package io.github.censodev.springbootauthexample;

import java.util.Collection;

public interface AuthService {
    Tokens login(String usn, String pwd);

    void signup(String usn, String pwd, Collection<User.RoleEnum> roles);
}
