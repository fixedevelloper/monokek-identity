package com.monokek.identity.domain;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@NoRepositoryBean
public interface UserRepository extends Repository<User, Long> {

    User save(User user);

    Optional<User> findById(Long id);

    List<User> findAll();

    Optional<User> findByEmail(String email);

    Optional<User> findByUuid(UUID uuid);

    boolean existsByEmail(String email);

    List<User> findByIdIn(Collection<Long> ids);
}
