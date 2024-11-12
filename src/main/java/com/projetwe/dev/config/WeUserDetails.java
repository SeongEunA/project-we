package com.projetwe.dev.config;

import com.projetwe.dev.model.WeUser;
import com.projetwe.dev.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class WeUserDetails implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        String password = null;
        List<GrantedAuthority> authorities = null;
        WeUser weuser = userRepository.findByEmail(username);

        if (weuser != null) {
            password = weuser.getPwd();
            authorities = new ArrayList<>();

            authorities.add(new SimpleGrantedAuthority(weuser.getRole()));
        } else {
            throw new UsernameNotFoundException("user not found email is : " + username);
        }
            return new User(username,password,authorities);

    }
}
