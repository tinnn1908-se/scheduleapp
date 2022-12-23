package com.ngoctin.scheduleapp.repositories.user;

import com.ngoctin.scheduleapp.entities.User;
import org.springframework.stereotype.Repository;

@Repository
public interface MyUserRepos {
    public User createUser(User user);
    public User getUserByUsername(String username);

}
