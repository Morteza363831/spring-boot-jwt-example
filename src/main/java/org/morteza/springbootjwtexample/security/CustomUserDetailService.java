package org.morteza.springbootjwtexample.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Optional;

@Component
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    UserRepo userRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<UserEntity> userOptional = Optional.ofNullable(userRepo.findByUsername(username));

        org.springframework.security.core.userdetails.User.UserBuilder userBuilder;

        if (userOptional.isPresent()) {

            UserEntity user = userOptional.get();
            userBuilder = org.springframework.security.core.userdetails.User.withUsername(username);
            userBuilder.password(passwordEncoder.encode(user.getPassword()));

            String[] roles = user.getAuthorities().split(",");

            userBuilder.authorities(roles);
        } else {
            throw new UsernameNotFoundException("User does not exist");
        }

        return userBuilder.build();
    }
}