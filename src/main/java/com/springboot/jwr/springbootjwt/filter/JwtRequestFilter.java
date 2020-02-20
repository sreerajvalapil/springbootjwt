package com.springboot.jwr.springbootjwt.filter;

import com.springboot.jwr.springbootjwt.service.MyUserDetailsService;
import com.springboot.jwr.springbootjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    MyUserDetailsService userDetailsService ;

    @Autowired
    JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = httpServletRequest.getHeader("Authorization") ;
        if(authHeader != null) {
            String jwt = authHeader.substring(7) ;
            System.out.println("The JWT is ........... ;" + jwt);
            String userName = jwtUtil.extractUserName(jwt) ;
            if(userName!=null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName) ;
                if(jwtUtil.validateToken(jwt,userDetails)) {
                    UsernamePasswordAuthenticationToken userToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,null,userDetails.getAuthorities());
                    userToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(userToken);

                }
            }
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);


    }
}
