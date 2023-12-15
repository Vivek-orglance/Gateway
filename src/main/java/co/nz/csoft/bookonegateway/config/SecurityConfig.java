package co.nz.csoft.bookonegateway.config;

import co.nz.csoft.bookonegateway.filter.AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AuthenticationFilter authenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges ->
                        exchanges
                                .pathMatchers("/auth/register", "/auth/token", "/eureka").permitAll()
                                .pathMatchers("/zomato/**").hasAuthority("ROLE_admin")
                                .pathMatchers("/restaurant/**").permitAll()
                                .anyExchange().authenticated()
                )
                .addFilterAt(authenticationFilter.createAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf(csrf -> csrf.disable())
                .build();
    }
}


