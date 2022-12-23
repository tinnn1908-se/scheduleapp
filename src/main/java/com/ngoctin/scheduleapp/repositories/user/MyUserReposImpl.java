package com.ngoctin.scheduleapp.repositories.user;

import com.ngoctin.scheduleapp.AppUtils;
import com.ngoctin.scheduleapp.entities.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RequiredArgsConstructor
@Slf4j
@Repository
public class MyUserReposImpl implements MyUserRepos {
    @PersistenceContext
    private final EntityManager entityManager;

    @Override
    @Transactional
    public User createUser(User user)  {
        try {
            String sql = "insert into users values(?,?,?,?,?,?)";
            Query query = entityManager.createNativeQuery(sql,User.class);
            query.setParameter(1, AppUtils.generateID());
            query.setParameter(2, user.getUsername());
            query.setParameter(3,user.getPassword());
            query.setParameter(4,user.getEmail());
            query.setParameter(5,user.getFullname());
            query.setParameter(6,user.getRole());
            int result = query.executeUpdate();
            if(result > 0) return user;
            return null;
        }catch (Exception exception){
            log.atWarn();
            log.warn(exception.getMessage());
            return  null;
        }
    }

    @Override
    public User getUserByUsername(String username){
        String sql = "SELECT * FROM users WHERE username = ?";
        log.info("username : " + username);
        Query query = entityManager.createNativeQuery(sql,User.class);
        query.setParameter(1,username);
        try {
            User user = (User)query.getResultList().stream().findFirst().get();
            log.info("User : " + user.toString());
            return user;
        }catch (Exception exception){
            log.error(exception.toString());
            log.atError();
            return  null;
        }
    }
}
