package com.ngoctin.scheduleapp.security;

import com.ngoctin.scheduleapp.filter.MyAuthentication;
import com.ngoctin.scheduleapp.filter.MyAuthorization;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@EnableWebSecurity
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration  = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        return source;
    }

   @Bean
   public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
       authenticationProvider.setUserDetailsService(userDetailsService);
       authenticationProvider.setPasswordEncoder(passwordEncoder);
       return authenticationProvider;
   }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception, AuthenticationException {
        MyAuthentication myAuthentication = new MyAuthentication(authenticationProvider());
        MyAuthorization myAuthorization = new MyAuthorization();
        http.csrf().disable();
        http.cors().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeHttpRequests((authorize)-> authorize
                .requestMatchers("/api/login/**","/api/register/**","/api/test/**").permitAll());
        myAuthentication.setFilterProcessesUrl("/api/login");
        http.addFilter(myAuthentication);
        http.addFilterBefore(myAuthorization, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(true)
                .ignoring()
                .requestMatchers("/css/**", "/js/**", "/img/**", "/lib/**", "/favicon.ico");
    }

}
