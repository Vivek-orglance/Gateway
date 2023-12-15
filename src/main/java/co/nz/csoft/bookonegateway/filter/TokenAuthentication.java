package co.nz.csoft.bookonegateway.filter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class TokenAuthentication extends UsernamePasswordAuthenticationToken {

    public TokenAuthentication(UserDetails principal, Collection<? extends GrantedAuthority> authorities) {
        super(principal, null, authorities);
    }

    public static TokenAuthentication from(Authentication authentication) {
        if (authentication == null || !TokenAuthentication.class.isAssignableFrom(authentication.getClass())) {
            return null;
        }
        return (TokenAuthentication) authentication;
    }
}
