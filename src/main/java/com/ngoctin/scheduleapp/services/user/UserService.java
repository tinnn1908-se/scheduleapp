package com.ngoctin.scheduleapp.services.user;

import com.ngoctin.scheduleapp.entities.User;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    public User createUser(User user);
    public User getUserByUsername(String username);
}
