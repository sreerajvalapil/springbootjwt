package com.springboot.jwr.springbootjwt.rest;

import com.springboot.jwr.springbootjwt.model.AuthenticationRequest;
import com.springboot.jwr.springbootjwt.model.AuthenticationResponse;
import com.springboot.jwr.springbootjwt.service.MyUserDetailsService;
import com.springboot.jwr.springbootjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class MyRestController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService ;

    @Autowired
    private JwtUtil jwtUtil ;

    @GetMapping("/getMessage")
    public String getHello() {
        return "Hai Good Evening" ;
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthToken(@RequestBody AuthenticationRequest authRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUserName(),authRequest.getPassword())) ;

        } catch (BadCredentialsException ex) {
            throw new Exception("Invalid user name and password" ,ex) ;
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUserName()) ;
        return ResponseEntity.ok(new AuthenticationResponse(jwtUtil.generateToken(userDetails))) ;

    }
}
