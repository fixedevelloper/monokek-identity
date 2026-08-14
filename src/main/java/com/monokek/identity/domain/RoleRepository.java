package com.monokek.identity.domain;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;

@NoRepositoryBean
public interface RoleRepository extends Repository<Role, Long> {

    Role save(Role role);

    List<Role> findAll();

    Optional<Role> findByName(String name);

    List<Role> findByNameNot(String name);
}
