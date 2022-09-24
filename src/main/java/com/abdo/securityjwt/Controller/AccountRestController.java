package com.abdo.securityjwt.Controller;


import ch.qos.logback.core.net.ObjectWriter;
import com.abdo.securityjwt.Utils.JWTUtil;
import com.abdo.securityjwt.entity.AppRole;
import com.abdo.securityjwt.entity.AppUser;
import com.abdo.securityjwt.service.AccountService;
;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@AllArgsConstructor
public class AccountRestController {

    private AccountService accountService;




    @GetMapping(path = "/users")
    public List<AppUser> appUser() {
        return accountService.listUsers();
    }


    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/users")
    public AppUser saveUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRole());

    }


    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {


    String jwtAuthenticationToken=request.getHeader(JWTUtil.AUTH_HEADER);
    if(jwtAuthenticationToken != null && jwtAuthenticationToken.startsWith(JWTUtil.PREFIX)){
        try{
            String jwt = jwtAuthenticationToken.substring(JWTUtil.PREFIX.length());
            Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
            JWTVerifier jwtVerifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
            String username = decodedJWT.getSubject();
            AppUser appUser = accountService.loadUserByUsername(username);
            String jwtAccessToken = JWT.create()
                    .withSubject(username)
                    .withClaim("roles", appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                    .withIssuer(request.getRequestURI().toString())
                    .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                    .sign(algorithm);
            Map<String, String> idToken = new HashMap<>();
            idToken.put("access-token", jwtAccessToken);
            idToken.put("refresh-token", jwt);
            new ObjectMapper().writeValue(response.getOutputStream(),idToken);
        }catch(Exception e){
            response.setHeader("error-message",e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }

    }else{
        throw  new RuntimeException("refresh token required");

    }

    }

    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }


}

@Data
class RoleUserForm{
    private String username;
    private String role;
}