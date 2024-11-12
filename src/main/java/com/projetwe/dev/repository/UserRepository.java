package com.projetwe.dev.repository;

import com.projetwe.dev.model.WeUser;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<WeUser, Long> {
    WeUser findByEmail(String email);
    WeUser save(WeUser weuser);
}
