package com.monokek.identity.domain;

import com.monokek.identity.common.Timestamps;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Aggregate root, single writer of the {@code users} table. Physically still in
 * monokek-spring's schema (see monokek-identity's package-level README/pom) — only
 * this service is allowed to write to it now; monokek-spring reads user data through
 * the HTTP UserDirectory/CurrentUser claims instead of JPA.
 */
@Entity
@Table(name = "users")
@SQLRestriction("deleted_at is null")
@Getter
@NoArgsConstructor
public class User extends Timestamps {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(nullable = false, updatable = false, columnDefinition = "CHAR(36)")
    private UUID uuid;

    private String name;

    private String phone;

    @Column(name = "branch_id")
    private Long branchId;

    /** Bcrypt hash of the 4-digit quick-unlock PIN (never the raw PIN). */
    @Column(name = "pin_code")
    private String pinCode;

    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "remember_token")
    private String rememberToken;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new LinkedHashSet<>();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_permissions",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> directPermissions = new LinkedHashSet<>();

    @PrePersist
    void assignUuid() {
        if (uuid == null) {
            uuid = UUID.randomUUID();
        }
    }

    public static User register(String name, String email, String phone, String hashedPassword, Role role) {
        User user = new User();
        user.name = name;
        user.email = email;
        user.phone = phone;
        user.password = hashedPassword;
        user.roles.add(role);
        return user;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setBranchId(Long branchId) {
        this.branchId = branchId;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setPinCode(String pinCode) {
        this.pinCode = pinCode;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void updateDirectPermissions(Set<Permission> permissions) {
        this.directPermissions = new LinkedHashSet<>(permissions);
    }

    /** Soft-deletes the user. Also revokes any outstanding OAuth2 authorizations — see AuthorizationRevocationService. */
    public void revokeAccess() {
        this.deletedAt = LocalDateTime.now();
    }

    public Set<String> getAllPermissionNames() {
        Set<String> names = roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        directPermissions.forEach(p -> names.add(p.getName()));
        return names;
    }
}
