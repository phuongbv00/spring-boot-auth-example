package io.github.censodev.springbootauthexample;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class Tokens {
    private String accessToken;
    private String refreshToken;
}
