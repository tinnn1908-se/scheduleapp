package com.ngoctin.scheduleapp.controllers;

import com.ngoctin.scheduleapp.entities.User;
import com.ngoctin.scheduleapp.services.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user){
        if(userService.createUser(user) != null)
            return ResponseEntity.status(HttpStatus.OK).body("Create User Successfully !");
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("Create User Failed !");
    }

    @PostMapping("/test/{username}")
    public ResponseEntity<?> test(@PathVariable String username){
        User user = userService.getUserByUsername(username);
        log.info("username : " + username);
        if(user != null)
            return ResponseEntity.status(HttpStatus.OK).body(user.toString());
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("Create User Failed !");
    }

}
