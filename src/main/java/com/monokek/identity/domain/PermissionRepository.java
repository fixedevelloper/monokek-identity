package com.monokek.identity.domain;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;

import java.util.List;

@NoRepositoryBean
public interface PermissionRepository extends Repository<Permission, Long> {

    Permission save(Permission permission);

    List<Permission> findAll();

    List<Permission> findByNameIn(List<String> names);
}
