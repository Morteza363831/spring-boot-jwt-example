package org.morteza.springbootjwtexample.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

@Component
public class CustomAuthenticationManager implements AuthenticationManager {

    @Autowired
    private UserRepo userRepository;
    private PasswordEncoder passwordEncoder;
    private Logger log = Logger.getLogger(CustomAuthenticationManager.class.getName());
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Optional<UserEntity> user = Optional.ofNullable(userRepository.findByUsername(authentication.getName()));

        if (user.isPresent()) {
            if (passwordEncoder.matches(authentication.getCredentials().toString(), user.get().getPassword())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                List<String> userAuthorities = Arrays.stream(user.get().getAuthorities().split(",")).toList();
                for (String authority : userAuthorities) {
                    authorities.add(new SimpleGrantedAuthority(authority));
                }
                return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authorities);
            }
            else {
                log.warning("Invalid password");
            }
        }
        //log.warning("Invalid username");
        throw new BadCredentialsException("Invalid username");
    }
}
