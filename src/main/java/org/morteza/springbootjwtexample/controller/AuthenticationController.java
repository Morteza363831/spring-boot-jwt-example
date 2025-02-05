package org.morteza.springbootjwtexample.controller;


import org.morteza.springbootjwtexample.security.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthenticationController {

    @Autowired
    private UserRepo userRepository;
    @Autowired
    CustomAuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @PostMapping("/signup")
    public UserEntity signUp(@RequestBody UserEntity user) {
        user.setAuthorities("ROLE_USER");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        System.out.println(user.getUsername() + " " + user.getPassword());
        return userRepository.save(user);
    }

    @GetMapping("/user")
    public UserEntity getUser() {
        return userRepository.findByUsername("morteza");
    }

    @PostMapping("/token")
    public String token(@RequestParam String username, @RequestParam String password) {
          authenticate(username, password);
        final UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
        return jwtTokenUtil.generateToken(userDetails);
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
