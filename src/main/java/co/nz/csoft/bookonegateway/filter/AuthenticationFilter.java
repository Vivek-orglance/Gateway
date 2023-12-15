package co.nz.csoft.bookonegateway.filter;

import co.nz.csoft.bookonegateway.entity.User;
import co.nz.csoft.bookonegateway.repository.UserRepository;
import co.nz.csoft.bookonegateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component("customAuthenticationFilter")
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator routeValidator;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Order(Ordered.HIGHEST_PRECEDENCE)
    public WebFilter createAuthenticationFilter() {
        return (exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            HttpHeaders headers = exchange.getRequest().getHeaders();
            System.out.println("Request Headers: " + headers);

            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
                System.out.println(token);

//                try {
//                    UserDetails userDetails = validateTokenAndGetUserDetails(token);
//                    System.out.println(userDetails);
//                    SecurityContextHolder.getContext().setAuthentication(new TokenAuthentication(userDetails));
//
//                } catch (Exception e) {
//                    return Mono.error(new RuntimeException("Unauthorized access"));
//                }
                try {
                    UserDetails userDetails = validateTokenAndGetUserDetails(token);
                    SecurityContextHolder.getContext().setAuthentication(new TokenAuthentication(userDetails, userDetails.getAuthorities()));

                } catch (ExpiredJwtException e) {
                    System.out.println(e.getMessage());
                } catch (MalformedJwtException e) {
                    System.out.println(e.getMessage());
                } catch (Exception e) {
                    System.out.println("Error validating token" + e.getMessage());
                    return Mono.error(new RuntimeException("Unauthorized access"));
                }
            }

            return chain.filter(exchange);
        };
    }



//    private UserDetails validateTokenAndGetUserDetails(String token) {
//
//        String username;
//        List<String> roles;
//
//        try {
//            Claims claims = jwtUtil.parseToken(token);
//            username = claims.getSubject();
//            roles = claims.get("roles", List.class);
//            System.out.println(roles);
//        } catch (Exception e) {
//            throw new RuntimeException("Invalid or expired token");
//        }
//
//        User userEntity = userRepository.findByName(username);
//
//        if (userEntity == null) {
//            throw new UsernameNotFoundException("User not found: " + username);
//        }
//
//        List<GrantedAuthority> authorities = roles.stream()
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
//                .collect(Collectors.toList());
//
//        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
//                .username(username)
//                .password(userEntity.getPassword())
//                .roles(roles.toArray(new String[0]))
//                .build();
//
//        return userDetails;
//    }
    private UserDetails validateTokenAndGetUserDetails(String token) {
        String username;
        List<GrantedAuthority> authorities;

        try {
            Claims claims = jwtUtil.parseToken(token);
            username = claims.getSubject();
            authorities = jwtUtil.extractRolesFromToken(token);
            System.out.println(authorities);
        } catch (Exception e) {
            throw new RuntimeException("Invalid or expired token");
        }

        User userEntity = userRepository.findByName(username);

        if (userEntity == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(username)
                .password(userEntity.getPassword())
//                .authorities(authorities.stream().map(Object::toString).toArray(String[]::new))
                .authorities(authorities)
                .build();


        return userDetails;
    }


    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
                System.out.println(token);

                try {
                    UserDetails userDetails = validateTokenAndGetUserDetails(token);
                    System.out.println(userDetails);
                    SecurityContextHolder.getContext().setAuthentication(new TokenAuthentication(userDetails, userDetails.getAuthorities()));

                } catch (Exception e) {
                    return Mono.error(new RuntimeException("Unauthorized access"));
                }
            }

            return chain.filter(exchange);
        };
    }


    public static class Config {

    }
}
