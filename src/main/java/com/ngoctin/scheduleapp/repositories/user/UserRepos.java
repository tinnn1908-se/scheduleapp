package com.ngoctin.scheduleapp.repositories.user;

import com.ngoctin.scheduleapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepos extends JpaRepository<User, String>,MyUserRepos {
}
