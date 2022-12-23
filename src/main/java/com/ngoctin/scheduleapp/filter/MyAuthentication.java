package com.ngoctin.scheduleapp.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
@Slf4j
public class MyAuthentication extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationProvider authenticationProvider;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username : " + username);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(username,password);
        return authenticationProvider.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        try {
            Algorithm algorithm = Algorithm.HMAC256("ngoctin".getBytes());
            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .withIssuer(request.toString())
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(30)))
                    .sign(algorithm);
            String refreshToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .withIssuer(request.toString())
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(3)))
                    .sign(algorithm);
            Map<String,String> tokens = new HashMap<>();
            tokens.put("accessToken",accessToken);
            tokens.put("refreshToken",refreshToken);
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_OK);
            new ObjectMapper().writeValue(response.getOutputStream(),tokens);
        }catch (Exception exception){
            Map<String,String> error = new HashMap<>();
            error.put("error",exception.getMessage());
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            new ObjectMapper().writeValue(response.getOutputStream(),error);
        }
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        new ObjectMapper().writeValue(response.getOutputStream(),"Login Failed !");
    }
}
