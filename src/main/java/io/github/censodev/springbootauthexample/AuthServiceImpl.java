package io.github.censodev.springbootauthexample;

import io.github.censodev.jwtprovider.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtProvider tokenProvider;

    @Override
    public Tokens login(String usn, String pwd) {
        return userRepository.findByUsername(usn)
                .filter(u -> passwordEncoder.matches(pwd, u.getPassword()))
                .map(u -> Tokens.builder()
                        .accessToken(tokenProvider.generate(u))
                        .refreshToken(tokenProvider.generate(u, 86_400_000))
                        .build())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    @Override
    public void signup(String usn, String pwd, Collection<User.RoleEnum> roles) {
        userRepository.save(User.builder()
                .username(usn)
                .password(passwordEncoder.encode(pwd))
                .roles(Optional.ofNullable(roles)
                        .orElse(Arrays.asList(
                                User.RoleEnum.ROLE_ADMIN,
                                User.RoleEnum.ROLE_MODERATOR,
                                User.RoleEnum.ROLE_GUEST
                        )))
                .build());
    }
}
