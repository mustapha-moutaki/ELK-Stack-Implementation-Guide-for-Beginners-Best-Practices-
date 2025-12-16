Here is the complete, step-by-step documentation for implementing JWT Authentication with Refresh Tokens in Spring Boot. This guide follows the standard architecture you can use in any project.

---

# 📘 JWT Authentication Implementation Guide

### 🏗️ Project Structure
Follow this package structure for any Spring Security project:
*   `config`: Global configurations.
*   `model`: Database entities.
*   `repository`: Data access layers.
*   `dto`: Data Transfer Objects.
*   `security`: Security-specific logic & filters.
*   `service`: Business logic.
*   `controller`: API endpoints.

---

### Step 1: Configuration Properties
**File:** `src/main/resources/application.yml`
**Purpose:** Centralizes sensitive configuration like the JWT Secret Key and Database credentials.

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/supplychainx_db # DB Connection URL
    username: supplychainx_user # DB Username
    password: supplychainx_pass # DB Password
  jpa:
    hibernate:
      ddl-auto: update # Automatically updates DB schema based on Entities

# JWT Specific Config
application:
  jwt:
    secret: 404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970 # 256-bit Hex Key
    access-token-expiration: 900000      # 15 mins (in ms)
    refresh-token-expiration: 604800000  # 7 days (in ms)
```
*   **Line 1-5:** Standard Database connection setup.
*   **Line 8:** `ddl-auto: update` keeps your DB table structure in sync with your Java classes.
*   **Line 13:** The Secret Key used to sign the tokens (Must be kept private).

---

### Step 2: User Entity
**File:** `model/User.java`
**Purpose:** Represents the user in the database.

*(Assuming standard User class with Lombok)*
```java
@Entity 
@Data 
@Builder 
@NoArgsConstructor 
@AllArgsConstructor
@Table(name = "_user") // 'user' is a reserved keyword in PostgreSQL
public class User implements UserDetails { // Implements Security interface
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    @Column(unique = true)
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    
    // UserDetails methods implementation...
}
```
*   **Line 1:** `@Entity` tells Hibernate to make a table out of this class.
*   **Line 6:** `implements UserDetails` allows Spring Security to understand this class.
*   **Line 7:** `@Table(name = "_user")` avoids SQL syntax errors with reserved keywords.

---

### Step 3: Refresh Token Entity
**File:** `model/RefreshToken.java`
**Purpose:** Stores the long-lived token linked to a specific user.

```java
@Entity
@NoArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token; // The actual UUID string

    @Column(nullable = false)
    private Instant expiryDate; // When this token dies

    @OneToOne // One user has exactly one active refresh token
    @JoinColumn(name = "user_id")
    private User user;

    // Getters and Setters manually added (as per previous fix)
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    // ... other getters/setters
}
```
*   **Line 10:** `Instant` is used for precise time calculation for expiration.
*   **Line 13:** `@OneToOne` creates a strict relationship between a token and a user.

---

### Step 4: Repositories
**Files:** `repository/user/UserRepository.java` & `repository/jwtAuth/RefreshTokenRepository.java`
**Purpose:** Interfaces to talk to the database.

```java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email); // Used for login
}

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token); // Used to validate token
    Optional<RefreshToken> findByUser(User user); // Used to update existing token
}
```
*   **Line 2:** `findByEmail` enables Spring to look up users by their login ID.
*   **Line 6:** `findByToken` allows retrieving the token object when the user sends the string.
*   **Line 7:** `findByUser` is crucial for "Token Rotation" (updating the old token instead of creating duplicates).

---

### Step 5: UserDetails Adapter
**File:** `security/CustomUserDetails.java`
**Purpose:** Bridges the gap between your Database User and Spring Security's internal user.

```java
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {
    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (user.getRole() == null) return List.of();
        // Converts Enum Role to Spring Authority
        return List.of(new SimpleGrantedAuthority(user.getRole().name())); 
    }
    // ... Returns user password and email for other methods
}
```
*   **Line 9:** Spring Security needs permissions as `GrantedAuthority` objects, not Enums, so we convert them here.

---

### Step 6: JWT Service (The Core)
**File:** `security/JwtService.java`
**Purpose:** Handles crypto logic: creating tokens, signing them, and extracting data.

```java
@Service
public class JwtService {
    @Value("${application.jwt.secret}")
    private String secretKey; // Injected from application.yml

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername()) // Sets the email as subject
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Encrypts it
                .compact();
    }
    // ... extractUsername, isTokenValid, getSignInKey
}
```
*   **Line 8:** Uses the Builder pattern to create the JWT payload.
*   **Line 11:** Signs the token using HMAC-SHA256, making it tamper-proof.

---

### Step 7: Application Configuration
**File:** `config/ApplicationConfig.java`
**Purpose:** Defines the "Beans" (Components) Spring needs to perform authentication.

```java
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        // Lambda function to find user or throw error
        return email -> userRepository.findByEmail(email)
                .map(CustomUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); // Sets how to find users
        authProvider.setPasswordEncoder(passwordEncoder()); // Sets how to decode passwords
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Uses BCrypt for hashing
    }
}
```
*   **Line 9:** Defines how Spring finds a user. It connects the Repository to the Security Context.
*   **Line 16:** The `AuthenticationProvider` is the logic engine that checks "Does password match hash?".

---

### Step 8: JWT Filter
**File:** `security/JwtAuthenticationFilter.java`
**Purpose:** Intercepts every HTTP request to check if a valid JWT is present.

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // ... imports dependencies

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        final String authHeader = request.getHeader("Authorization"); // 1. Get header
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // 2. If no token, continue (Spring Security will block it later if needed)
            return;
        }

        final String jwt = authHeader.substring(7); // 3. Remove "Bearer " prefix
        final String userEmail = jwtService.extractUsername(jwt); // 4. Extract email

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            
            if (jwtService.isTokenValid(jwt, userDetails)) { // 5. Validate token
                // 6. Create Auth Token object and set it in Context
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response); // 7. Pass request to next filter
    }
}
```

---

### Step 9: Security Configuration
**File:** `config/SecurityConfiguration.java`
**Purpose:** The Rulebook. Decides which endpoints are public and which are private.

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
            .csrf(AbstractHttpConfigurer::disable) // Disable CSRF (not needed for stateless APIs)
            .authorizeHttpRequests(req -> req
                .requestMatchers("/api/auth/**").permitAll() // Allow Login/Register without token
                .anyRequest().authenticated() // Block everything else
            )
            .sessionManagement(session -> session.sessionCreationPolicy(STATELESS)) // No Server Sessions (JWT is stateless)
            .authenticationProvider(authenticationProvider) // Use our custom provider
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // Run JWT filter before standard filter

        return http.build();
    }
}
```

---

### Step 10: Refresh Token Service
**File:** `service/jwtAuth/RefreshTokenService.java`
**Purpose:** Manages the lifecycle of the refresh token.

```java
@Service
public class RefreshTokenService {
    // ... dependencies

    public RefreshToken createRefreshToken(String username) {
        var user = userRepository.findByEmail(username).orElseThrow();
        
        // Logic to rotate token: Get existing OR create new
        RefreshToken refreshToken = refreshTokenRepository.findByUser(user)
                .orElse(new RefreshToken());

        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString()); // Generate random UUID

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token); // Delete if expired
            throw new RuntimeException("Token expired"); // In real app, create custom exception
        }
        return token;
    }
}
```

---

### Step 11: Authentication Service
**File:** `service/jwtAuth/AuthenticationService.java`
**Purpose:** Business logic for Registering and Logging in.

```java
@Service
public class AuthenticationService {
    // ... dependencies

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                // ... map fields
                .password(passwordEncoder.encode(request.getPassword())) // Hash password
                .build();
        userRepository.save(user);
        
        // Generate both tokens
        var jwtToken = jwtService.generateToken(new CustomUserDetails(user));
        var refreshToken = refreshTokenService.createRefreshToken(user.getEmail());
        
        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken.getToken()).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // This validates the email/password combination automatically
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        
        // Generate new tokens
        var jwtToken = jwtService.generateToken(new CustomUserDetails(user));
        var refreshToken = refreshTokenService.createRefreshToken(user.getEmail());
        
        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken.getToken()).build();
    }
}
```

---

### Step 12: Auth Controller
**File:** `controller/auth/AuthController.java`
**Purpose:** The entrance for the API.

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(service.refreshToken(request.getToken()));
    }
}
```


Here is the **Golden Template Order** to follow in any Spring Boot JWT project:

### Phase 1: Foundation (Data & Settings)
*Build these first because they don't depend on anything else.*

1.  **`application.yml`**
    *   **Why:** Define your Secret Key and Expiration times so you can inject them later.
2.  **`model/User.java`** & **`model/RefreshToken.java`**
    *   **Why:** You can't create repositories or services without the database entities.
3.  **`repository/UserRepository.java`** & **`repository/RefreshTokenRepository.java`**
    *   **Why:** You need these interfaces to fetch data in your services.
4.  **`dto/Auth/*.java`** (Request/Response classes)
    *   **Why:** Define the structure of your JSON inputs/outputs so your Services know what data to expect.

---

### Phase 2: Security Utilities & Logic
*Build these next. They use the foundation to do the actual work.*

5.  **`security/CustomUserDetails.java`**
    *   **Why:** Spring Security doesn't know your `User` entity. This adapter bridges the gap.
6.  **`security/JwtService.java`**
    *   **Why:** The utility tool to generate and validate tokens. It uses the `application.yml` values.
7.  **`service/jwtAuth/RefreshTokenService.java`**
    *   **Why:** Handles the specific logic for creating and rotating the long-lived tokens using the Repositories.
8.  **`config/ApplicationConfig.java`**
    *   **Why:** Configures the `PasswordEncoder` and `AuthenticationManager` beans that the main Auth service needs.
9.  **`service/jwtAuth/AuthenticationService.java`**
    *   **Why:** The "Brain". It brings everything together (UserRepo, JwtService, RefreshTokenService) to register and login users.

---

### Phase 3: Wiring & Infrastructure
*Now you connect the logic to the HTTP Web Layer.*

10. **`security/JwtAuthenticationFilter.java`**
    *   **Why:** The "Gatekeeper". It uses `JwtService` and `UserDetailsService` to check headers before the request hits the controller.
11. **`config/SecurityConfiguration.java`**
    *   **Why:** The "Rulebook". It tells Spring to use your Filter, disable CSRF, and allow access to `/api/auth/**`.

---

### Phase 4: Exposure (The API)
*The final step.*

12. **`controller/auth/AuthController.java`**
    *   **Why:** The "Door". It simply receives the Request DTOs, calls the `AuthenticationService`, and returns the Response DTOs.

---

### 🧠 Quick Mental Check
If you are ever confused about the order, just ask yourself:
**"Can I write this class yet?"**

*   *Can I write the Controller?* **No**, it needs the Service.
*   *Can I write the Service?* **No**, it needs the Repository.
*   *Can I write the Repository?* **No**, it needs the Entity.
*   *Can I write the Entity?* **Yes! Start here.**
