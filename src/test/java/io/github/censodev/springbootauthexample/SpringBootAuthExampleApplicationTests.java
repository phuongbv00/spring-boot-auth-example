package io.github.censodev.springbootauthexample;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SpringBootAuthExampleApplicationTests {
    @LocalServerPort
    int port;
    @Autowired
    TestRestTemplate restTemplate;
    @Autowired
    ObjectMapper objectMapper;

    @Test
    void fullFlow() throws JsonProcessingException {
        // get unauthorized when access without access token
        ResponseEntity<User> profileRes = profile(null);
        assertEquals(HttpStatus.UNAUTHORIZED, profileRes.getStatusCode());

        // get unauthorized when access with invalid token
        profileRes = profile("invalid_token");
        assertEquals(HttpStatus.UNAUTHORIZED, profileRes.getStatusCode());

        // signup
        ResponseEntity<Void> signupRes = signup("usn", "pwd");
        assertEquals(HttpStatus.OK, signupRes.getStatusCode());

        // login with invalid credentials
        ResponseEntity<String> loginRes = login("usn", "pwd1");
        assertEquals(HttpStatus.UNAUTHORIZED, loginRes.getStatusCode());
        loginRes = login("usn1", "pwd");
        assertEquals(HttpStatus.UNAUTHORIZED, loginRes.getStatusCode());

        // login with valid credentials
        loginRes = login("usn", "pwd");
        assertEquals(HttpStatus.OK, loginRes.getStatusCode());

        // get access token after login
        Tokens tokens = objectMapper.readValue(loginRes.getBody(), Tokens.class);
        assertNotNull(tokens.getRefreshToken());
        String accessToken = tokens.getAccessToken();

        // access with access token
        profileRes = profile(accessToken);
        assertEquals(HttpStatus.OK, profileRes.getStatusCode());
        User profileResBody = profileRes.getBody();
        assertNotNull(profileResBody);
        assertEquals(1L, profileResBody.getId());
        assertEquals("usn", profileResBody.getUsername());
        assertTrue(profileResBody.getRoles().contains(User.RoleEnum.ROLE_ADMIN));
        assertTrue(profileResBody.getRoles().contains(User.RoleEnum.ROLE_MODERATOR));
        assertTrue(profileResBody.getRoles().contains(User.RoleEnum.ROLE_GUEST));
    }

    private ResponseEntity<User> profile(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        HttpEntity<Void> request = new HttpEntity<>(headers);
        return restTemplate.exchange(url("/api/auth/profile"), HttpMethod.GET, request, User.class);
    }

    private ResponseEntity<String> login(String usn, String pwd) {
        Map<String, String> params = new HashMap<String, String>() {{
            put("usn", usn);
            put("pwd", pwd);
        }};
        return restTemplate.getForEntity(url("/api/auth/login?usn={usn}&pwd={pwd}"), String.class, params);
    }

    private ResponseEntity<Void> signup(String usn, String pwd) {
        Map<String, String> params = new HashMap<String, String>() {{
            put("usn", usn);
            put("pwd", pwd);
        }};
        return restTemplate.getForEntity(url("/api/auth/signup?usn={usn}&pwd={pwd}"), Void.class, params);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
