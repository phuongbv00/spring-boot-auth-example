package io.github.censodev.springbootauthexample;

import io.github.censodev.jwtprovider.CanAuth;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements CanAuth {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;

    @CreationTimestamp
    private Instant createdAt;

    @ElementCollection
    private Collection<RoleEnum> roles;

    @Override
    public Object subject() {
        return id;
    }

    @Override
    public Collection<String> authorities() {
        return roles.stream()
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    public enum RoleEnum {
        ROLE_ADMIN,
        ROLE_MODERATOR,
        ROLE_GUEST
    }
}
