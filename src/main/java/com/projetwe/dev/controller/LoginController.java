package com.projetwe.dev.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.projetwe.dev.config.ProjectWeAuthenticationProvider;
import com.projetwe.dev.constants.ApplicationConstants;
import com.projetwe.dev.filter.JWTTokenGeneratorFilter;
import com.projetwe.dev.model.WeUser;
import com.projetwe.dev.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.boot.logging.log4j2.Log4J2LoggingSystem.getEnvironment;

@RestController
public class LoginController {

    @Autowired
    UserRepository UserRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    ProjectWeAuthenticationProvider authenticationProvider;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody WeUser weUser) {

        WeUser savedWeUser = null;
        ResponseEntity response = null;

        try {
            String encodedPassword = passwordEncoder.encode(weUser.getPwd());
            weUser.setPwd(encodedPassword);
            savedWeUser = UserRepository.save(weUser);
            if(savedWeUser.getId() > 0) {
                response = ResponseEntity.status(HttpStatus.CREATED)
                        .body("Given user details are successfully regsitered");
            }
        } catch (Exception ex) {
            response = ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An exception occured due to " + ex.getMessage());
        }
        return  response;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticateUser(HttpServletResponse response, @RequestBody WeUser weUser) {

        // UsernamePasswordAuthenticationToken 객체로 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(weUser.getEmail(), weUser.getPwd());

        try {
            // AuthenticationManager를 통해 인증 시도
            Authentication authentication = authenticationProvider.authenticate(authenticationToken);

            // 인증 성공 후 SecurityContext에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Map<String,String> responseMap = new HashMap<>();
            responseMap.put("msg", "Authentication successful");

            String secret = ApplicationConstants.JWT_VALUE;
            SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            Map<String, Object> claim = new HashMap<>();
            claim.put("username", authentication.getName());
            claim.put("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")));
            String jwt = Jwts.builder().setIssuer("ProjectWe").setSubject("JWT Token")
                    .setClaims(claim)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 30000000))
                    .signWith(secretKey).compact();

            responseMap.put("jwtToken",jwt);
            ObjectMapper mapper = new ObjectMapper();
            String jsonResponse = mapper.writeValueAsString(responseMap);
            // 인증 성공 응답 반환
            return ResponseEntity.ok(jsonResponse);

        } catch (AuthenticationException e) {
            // 인증 실패 응답 반환
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed");
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
