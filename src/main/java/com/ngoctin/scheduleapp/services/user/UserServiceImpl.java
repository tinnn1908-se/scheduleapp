package com.ngoctin.scheduleapp.services.user;

import com.ngoctin.scheduleapp.entities.User;
import com.ngoctin.scheduleapp.repositories.user.UserRepos;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    public final UserRepos userRepos;
    public final PasswordEncoder passwordEncoder;

    @Override
    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if(userRepos.createUser(user) != null) return user;
        return  null;
    }

    @Override
    public User getUserByUsername(String username) {
        return userRepos.getUserByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepos.getUserByUsername(username);
        if(user != null){
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority(user.getRole()));
            return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),authorities);
        }
        return null;
    }
}
