package com.jilinwula.security.dao;

import com.jilinwula.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User,Long> {
    User findUserByUsername(String username);
}

