Okay, I'll provide you with a best-practice implementation of JWT authentication in Spring Boot, built upon the guide you provided, and highlight potential "mistakes" (areas for improvement) and how to fix them. I'll focus on the essential aspects while aiming for a robust and secure setup.

**Core Principles of Best Practice JWT Authentication**

*   **Security First:** Always prioritize the security of your users' data and the system itself.
*   **Separation of Concerns:** Keep code modular and focused on specific responsibilities.
*   **Modern Practices:** Utilize the latest Spring Security features and best-known methods.
*   **Robustness:** Implement features like refresh token rotation and revocation.

---

### Best Practice Implementation: Step-by-Step with Fixes

Here's the refined approach, with explanations, and "mistake" identification:

**1. Add Dependencies (Correct - No changes needed)**

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.5</version>  <!-- Or the latest version -->
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.5</version>  <!-- Or the latest version -->
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.5</version>  <!-- Or the latest version -->
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <!-- Database Dependencies (Choose one) -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

**2. User Entity (Improved)**

*   **Model/User.java**

```java
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users") // Good practice: specify table name
public class User { // NO implements UserDetails!
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true) // Important: username should be unique
    private String username;

    private String password; // Store hashed password!

    private String role; // e.g., "USER", "ADMIN"
}
```

**Mistake:** Implementing `UserDetails` directly. This couples your database entity to Spring Security.

**Fix:** Remove `implements UserDetails` from the `User` entity. Create a *separate* class (or a DTO) that *implements* `UserDetails` and *wraps* the `User` entity.

**3. UserDetails Implementation (Separate Class)**

*   **security/CustomUserDetails.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Or implement account expiry logic
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Or implement account locking logic
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Or implement credential expiry logic
    }

    @Override
    public boolean isEnabled() {
        return true; // Or implement account enabling/disabling logic
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomUserDetails that = (CustomUserDetails) o;
        return Objects.equals(user, that.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user);
    }
}
```

**4. User Repository (Correct - No changes needed)**

*   **repository/user/UserRepository.java**

```java
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}
```

**5. UserDetailsService Implementation**

*   **service/UserDetailsServiceImpl.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.supplychain.model.User;  // Adjust import
import com.example.supplychain.repository.user.UserRepository;  // Adjust import

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional // Good practice for database operations
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return new CustomUserDetails(user); // Use our custom implementation
    }
}
```

**6. Application Config (Enhanced)**

*   **config/ApplicationConfig.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

**7. JWT Properties / JWT Service (Essential)**

*   **security/JwtService.java**

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.jwt.secret}") // Use application.yml
    private String secretKey;
    @Value("${application.jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${application.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, accessTokenExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove "Bearer "
        }
        return null;
    }
}
```

**Mistake:** Storing the secret directly in the code or `application.yml`.

**Fix:**

1.  **Use Environment Variables:** In `application.yml`, use `${JWT_SECRET}`.
2.  **Environment Configuration:**  Set the `JWT_SECRET` environment variable (e.g., in your Docker setup, cloud provider, or local environment). Never hardcode the secret.

**8. JWT Authentication Filter (Core)**

*   **security/JwtAuthenticationFilter.java**

```java
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

**9. Security Configuration (Critical - BEST PRACTICE)**

*   **config/SecurityConfiguration.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // or configure csrf if needed
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // Public endpoints
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));  // Allow all origins (for development)
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setExposedHeaders(Arrays.asList("Authorization")); // Important for JWT
        configuration.setAllowCredentials(true); // Allow sending of cookies
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**Mistake:** Using the older `.and()` configuration.

**Fix:** Use the **Lambda DSL** (the newer, preferred style). This is more readable and aligns with Spring Boot's direction.

**10. Authentication & Refresh Token Services (Key Logic)**

*   **service/AuthService.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.supplychain.model.User;
import com.example.supplychain.repository.user.UserRepository;
import com.example.supplychain.security.JwtService;
import com.example.supplychain.security.CustomUserDetails;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;  // Inject AuthenticationManager

    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("USER") // Or use an enum for roles
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateAccessToken(new CustomUserDetails(user)); // Correct use
        var refreshToken = jwtService.generateRefreshToken(new CustomUserDetails(user));
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
        var jwtToken = jwtService.generateAccessToken(new CustomUserDetails(user));
        var refreshToken = jwtService.generateRefreshToken(new CustomUserDetails(user));
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
}
```

*   **service/RefreshTokenService.java**

```java
import com.example.supplychain.model.RefreshToken;
import com.example.supplychain.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    @Value("${application.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;

    public RefreshToken createRefreshToken(UserDetails userDetails) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userDetails.getUsername());  // Store username
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString()); // Generate a unique token
        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public boolean validateRefreshToken(String token) {
        try {
            RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                    .orElseThrow(() -> new TokenRefreshException(token, "Refresh token is not in database!"));
            verifyExpiration(refreshToken);
            return true;
        } catch (ExpiredJwtException e) {
            return false;
        }
    }

    public String generateAccessTokenFromRefreshToken(String refreshToken) {
        RefreshToken existingRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not in database!"));
        verifyExpiration(existingRefreshToken);
        UserDetails userDetails =  userDetailsServiceImpl.loadUserByUsername(existingRefreshToken.getUser());
        return jwtService.generateAccessToken(userDetails);

    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }
}
```

*   **model/RefreshToken.java**

```java
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Data
@NoArgsConstructor
@Table(name = "refreshtoken")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private String user;

}
```

*   **repository/RefreshTokenRepository.java**

```java
import com.example.supplychain.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);
    void deleteByToken(String token);
}
```

*   **service/TokenRefreshException.java**

```java
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TokenRefreshException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private String token;
  private String message;

  public TokenRefreshException(String token, String message) {
    super(String.format("Failed for [%s]: %s", token, message));
    this.token = token;
    this.message = message;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  @Override
  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}
```

**Mistake:** No database persistence for refresh tokens, or refresh token rotation.

**Fix:** Implement the following:

1.  **Database Entity:** Create a `RefreshToken` entity (shown above) to store tokens in the database.
2.  **Token Generation:** When a refresh token is issued:
    *   Generate a unique `UUID` for the token.
    *   Store the token, its expiration date, and the user associated with it in the database.
3.  **Token Validation:**
    *   When a refresh token is used, check:
        *   If the token exists in the database.
        *   If it is expired (e.g., `expiryDate` is in the past).
    *   If valid, issue a new access token and a **new** refresh token (and delete the old refresh token from the database - **Token Rotation**). This is *crucial* for security.
4.  **Token Revocation:**  Implement a way to revoke refresh tokens (e.g., on logout, account compromise).  This means deleting the relevant `RefreshToken` record from the database.

**11. Controller Layer (Correct - but with Refresh)**

*   **controller/auth/AuthController.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.supplychain.service.AuthService;
import com.example.supplychain.dto.AuthenticationRequest;
import com.example.supplychain.dto.AuthenticationResponse;
import com.example.supplychain.dto.RegisterRequest;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
```

*   **controller/auth/RefreshTokenController.java**

```java
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.supplychain.service.RefreshTokenService;
import com.example.supplychain.dto.RefreshTokenRequest;
import com.example.supplychain.dto.AuthenticationResponse;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            String accessToken = refreshTokenService.generateAccessTokenFromRefreshToken(refreshToken);
            AuthenticationResponse response = AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshTokenService.generateRefreshToken(userDetails)) // Generate a new refresh token (ROTATION!)
                    .build();
            return ResponseEntity.ok(response);
        } catch (TokenRefreshException e) {
            // Handle expired/invalid refresh token
            return ResponseEntity.status(403).build(); // Or send a specific error
        }
    }
}
```

*   **dto/AuthenticationRequest.java**

```java
import lombok.Data;

@Data
public class AuthenticationRequest {
    private String username;
    private String password;
}
```

*   **dto/AuthenticationResponse.java**

```java
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
}
```

*   **dto/RegisterRequest.java**

```java
import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String password;
}
```

*   **dto/RefreshTokenRequest.java**

```java
import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
```

**12. Application Properties / YAML (Enhanced)**

*   **application.yml**

```yaml
spring:
  application:
    name: your-app-name

  datasource:
    url: jdbc:postgresql://localhost:5432/your_db_name
    username: your_db_user
    password: your_db_password
    driver-class-name: org.postgresql.Driver

  jpa:
    hibernate:
      ddl-auto: update # Or "create", "validate", "none" (use with caution in prod)
      show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect

application:
  jwt:
    secret: ${JWT_SECRET}  # Use environment variable!
    access-token-expiration: 900000  # 15 minutes (in milliseconds)
    refresh-token-expiration: 604800000 # 7 days (in milliseconds)
```

**Mistake:** Hardcoding the secret.

**Fix:** Use an environment variable for `secret`.

**13. Final Folder Structure (Correct)**

```
src/main/java/com/example/supplychain/
├── config
│   ├── ApplicationConfig.java       # Security beans, password encoder
│   └── SecurityConfiguration.java  # Security filter chain, CORS
├── model
│   ├── User.java                    # User Entity
│   └── RefreshToken.java            # Refresh Token Entity
├── repository
│   ├── user
│   │   └── UserRepository.java      # User data access
│   └── RefreshTokenRepository.java # Refresh Token Data Access
├── security
│   ├── JwtService.java              # Generate & validate JWT
│   ├── JwtAuthenticationFilter.java # Filter incoming requests
│   └── CustomUserDetails.java       # UserDetails implementation
├── service
│   ├── AuthService.java
│   ├── RefreshTokenService.java
│   └── UserDetailsServiceImpl.java  # Loads UserDetails
├── controller
│   └── auth
│       ├── AuthController.java
│       └── RefreshTokenController.java
├── dto
│   ├── AuthenticationRequest.java
│   ├── AuthenticationResponse.java
│   ├── RegisterRequest.java
│   └── RefreshTokenRequest.java
└── Application.java
```

---

**Summary of Best Practices & Fixes:**

*   **Database-backed Refresh Tokens:** This is *critical* for security (revocation, rotation).
*   **Lambda DSL:** Use the modern Spring Security configuration style.
*   **Environment Variables:** Never hardcode secrets.
*   **DTOs/UserDetails:** Separate security concerns from your entity.
*   **Token Rotation:**  Generate a *new* refresh token every time a user uses one (in the Refresh Token controller).
*   **Error Handling:** Add a custom `AuthenticationEntryPoint` to handle JWT-related errors (e.g., expired tokens) and send the correct HTTP status codes to the frontend.

This revised implementation addresses the main areas for improvement and provides a solid foundation for secure JWT authentication in your Spring Boot application.  Remember to adapt this code to your specific project needs.



إليك الدليل الكامل والمحسّن لتطبيق **JWT Authentication** في **Spring Boot** مع اتباع **أفضل الممارسات (Best Practices)**.

لقد قمت بإصلاح الأخطاء الشائعة التي ذكرناها سابقاً، وقمت بكتابة الشرح باللغة العربية.

---

# 🛠️ تطبيق مصادقة JWT في Spring Boot - الدليل الاحترافي (أفضل الممارسات)

هذا الدليل يشرح كيفية بناء نظام حماية متكامل، مع إصلاح الأخطاء المعمارية الشائعة مثل دمج `UserDetails` مع `Entity`، وعدم تخزين `Refresh Token` في قاعدة البيانات.

### 1️⃣ إضافة المكتبات (Dependencies)

في ملف `pom.xml`، أضف المكتبات التالية. نحن نستخدم أحدث إصدارات `jjwt`.

```xml
<dependencies>
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- JWT Libraries -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.5</version>
        <scope>runtime</scope>
    </dependency>

    <!-- Database & Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId> <!-- أو H2 حسب اختيارك -->
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

---

### 2️⃣ كيان المستخدم (User Entity) - الطريقة الصحيحة

**الخطأ السابق:** تنفيذ `implements UserDetails` داخل الـ Entity مباشرة.
**التصحيح:** اجعل الـ Entity نظيفة (فقط للبيانات)، واستخدم كلاس منفصل للأمان.

**الملف:** `model/User.java`

```java
@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;
    
    private String password;
    
    private String role; // مثلاً ADMIN أو USER
}
```

---

### 3️⃣ فصل منطق الأمان (Custom UserDetails)

هذا الكلاس يربط بين المستخدم في قاعدة البيانات وبين Spring Security.

**الملف:** `security/CustomUserDetails.java`

```java
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole()));
    }

    @Override
    public String getPassword() { return user.getPassword(); }

    @Override
    public String getUsername() { return user.getUsername(); }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
```

---

### 4️⃣ مستودع المستخدم (User Repository)

**الملف:** `repository/UserRepository.java`

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}
```

---

### 5️⃣ إعدادات التطبيق (Application Config)

هنا نقوم بتعريف الـ Beans الخاصة بالأمان.

**الملف:** `config/ApplicationConfig.java`

```java
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .map(CustomUserDetails::new) // استخدام الـ Wrapper الذي أنشأناه
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

---

### 6️⃣ خدمة JWT (JWT Service)

**التحسين:** قراءة المفتاح السري (Secret Key) من الإعدادات وليس كود ثابت.

**الملف:** `security/JwtService.java`

```java
@Service
public class JwtService {

    @Value("${application.jwt.secret}") // قراءة من application.yml
    private String secretKey;
    @Value("${application.jwt.access-token-expiration}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

---

### 7️⃣ فلتر المصادقة (JWT Filter)

**الملف:** `security/JwtAuthenticationFilter.java`

```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

---

### 8️⃣ إعدادات الأمان (Security Config) - التحديث الهام

**الخطأ السابق:** استخدام أسلوب `.and()` القديم.
**التصحيح:** استخدام **Lambda DSL** الحديث (المعتمد في Spring Boot 3+).

**الملف:** `config/SecurityConfiguration.java`

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(req -> req
                .requestMatchers("/api/auth/**").permitAll() // السماح بالدخول لصفحات التسجيل
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

---

### 9️⃣ نظام Refresh Token (الأكثر أهمية)

**الخطأ السابق:** عدم وجود كيان `RefreshToken` في قاعدة البيانات.
**التصحيح:** إنشاء كيان في قاعدة البيانات وتفعيل خاصية "تدوير التوكن" (Token Rotation) للحماية من السرقة.

**الملف:** `model/RefreshToken.java`

```java
@Entity
@Data
@NoArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;
}
```

**الملف:** `service/RefreshTokenService.java`

```java
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    
    @Value("${application.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;

    public RefreshToken createRefreshToken(String username) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findByUsername(username).get());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }
    
    // هنا يمكن إضافة دالة لحذف التوكن القديم وإنشاء جديد (Rotation)
}
```

---

### 🔟 ملف الإعدادات (Application.yml)

**ملاحظة:** لا تضع كلمة السر الحقيقية هنا إذا كنت سترفع الكود على GitHub. استخدم متغيرات البيئة.

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/mydb
    username: myuser
    password: mypassword
  jpa:
    hibernate:
      ddl-auto: update

application:
  jwt:
    # استخدم Environment Variable للأمان
    secret: ${JWT_SECRET} 
    access-token-expiration: 900000      # 15 دقيقة
    refresh-token-expiration: 604800000  # 7 أيام
```

---

###  ملخص الأخطاء التي تم إصلاحها (Why this is Best Practice)

1.  **فصل المسؤوليات (Separation of Concerns):**
    *   **الخطأ:** `User implements UserDetails`.
    *   **الإصلاح:** قمنا بإنشاء `CustomUserDetails`. هذا يحمي قاعدة البيانات الخاصة بك من التغييرات في Spring Security ويجعل الكود أنظف.

2.  **تخزين Refresh Token:**
    *   **الخطأ:** الاعتماد على JWT فقط للـ Refresh Token (بدون قاعدة بيانات).
    *   **الإصلاح:** تخزين الـ Refresh Token في قاعدة البيانات (`RefreshToken Entity`). هذا يسمح لك بإلغاء صلاحية المستخدم (Revoke) إذا تم اختراق حسابه.

3.  **تحديث إعدادات الأمان:**
    *   **الخطأ:** استخدام `.and()` وسلاسل الأوامر القديمة.
    *   **الإصلاح:** استخدام **Lambda DSL** (`.authorizeHttpRequests(req -> ...)`). هذا هو المعيار الجديد والمستقبلي لـ Spring.

4.  **أمان المفاتيح (Secrets):**
    *   **الخطأ:** وضع `secret key` بشكل نصي وصريح في الكود.
    *   **الإصلاح:** الإشارة إلى استخدام متغيرات البيئة `${JWT_SECRET}`.

باتباعك لهذه الخطوات، ستحصل على نظام مصادقة **قوي، قابل للصيانة، وآمن** يتوافق مع معايير الصناعة الحديثة.
