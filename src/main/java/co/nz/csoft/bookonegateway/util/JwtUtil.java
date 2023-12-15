package co.nz.csoft.bookonegateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtil {


    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";


    public void validateToken(final String token) {
        Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token);
    }

    public String getSubjectFromToken(final String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims parseToken(String token) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(SECRET);
            Key key = Keys.hmacShaKeyFor(keyBytes);

            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JWT token", e);
        }
    }

    public List<GrantedAuthority> extractRolesFromToken(String token) {
        Claims claims = parseToken(token);
        List<String> roles = claims.get("roles", List.class);

        if (roles == null) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities =  roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());


        return authorities;
    }


}
