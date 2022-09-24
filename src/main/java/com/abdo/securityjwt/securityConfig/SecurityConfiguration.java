package com.abdo.securityjwt.securityConfig;


import com.abdo.securityjwt.filters.JWTAuthenticationFilter;
import com.abdo.securityjwt.filters.JWTAuthorizationFilter;
import com.abdo.securityjwt.service.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@AllArgsConstructor
@Configuration
public class SecurityConfiguration {
    private UserDetailsServiceImpl userDetailsService;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(csrf->csrf.disable());
        httpSecurity.sessionManagement(r->r.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.formLogin(r->{
            r.loginPage("/login");
        });
        httpSecurity.authorizeHttpRequests(auth->auth.requestMatchers("/refreshToken/**","/login/**").permitAll());
        httpSecurity.authorizeHttpRequests(auth->auth.anyRequest().authenticated());
        httpSecurity.userDetailsService(userDetailsService);
        httpSecurity.addFilter(new JWTAuthenticationFilter());
        httpSecurity.addFilterBefore(new JWTAuthorizationFilter(),UsernamePasswordAuthenticationFilter.class);


        return httpSecurity.build();
    }
}
