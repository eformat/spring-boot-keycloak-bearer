package com.example.productapp;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class ProductAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProductAppApplication.class, args);
    }
}

@Controller
class ProductController {

    @NotNull
    @Value("${service.url}")
    private String endpoint;

    @Autowired
    private KeycloakRestTemplate template;

    @Bean
    @Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public AccessToken accessToken() {
        try {
            HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                            .getRequest();
            return ((KeycloakSecurityContext) ((KeycloakAuthenticationToken) request
                    .getUserPrincipal())
                    .getCredentials()).getToken();
        } catch (Exception exc) {
            return null;
        }
    }

    @GetMapping(path = "/products")
    public String getProducts(Principal principal, Model model) {
        model.addAttribute("principal", principal);
        //System.out.println("AccessToken:" + accessToken());
        model.addAttribute("products", serviceProducts());
        return "products";
    }

    @GetMapping(path = "/logout")
    public String logout(HttpServletRequest request) throws ServletException {
        request.logout();
        return "/";
    }

    private List<String> serviceProducts() {
        ResponseEntity<String[]> response = template.getForEntity(endpoint, String[].class);
        return Arrays.asList(response.getBody());
    }

}

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @NotNull
    @Value("${keycloak.truststore}")
    private String keyStoreFile;

    @NotNull
    @Value("${keycloak.truststore-password}")
    private String keyStorePassword;

    @Autowired
    public KeycloakClientRequestFactory keycloakClientRequestFactory;

    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        // Load generated self signed cert keystore for template call
        try {
            File initialFile = new File(keyStoreFile);
            InputStream keyStoreInputStream = new FileInputStream(initialFile);
            if (keyStoreInputStream == null) {
                throw new FileNotFoundException("Could not find file named '" + keyStoreFile);
            }
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keyStoreInputStream, keyStorePassword.toCharArray());
            SSLContext sc = new SSLContextBuilder()
                    .loadTrustMaterial(keystore, (certificate, authType) -> true).build();
            CloseableHttpClient client = HttpClients.custom()
                    .setSSLContext(sc)
                    .setSSLHostnameVerifier(new NoopHostnameVerifier())
                    .build();
            keycloakClientRequestFactory.setHttpClient(client);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        System.out.println(">>> Loaded KeycloakRestTemplate with keystore");
        return new KeycloakRestTemplate(keycloakClientRequestFactory);
    }

    @Bean
    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
            KeycloakAuthenticationProcessingFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
            KeycloakPreAuthActionsFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .authorizeRequests()
                .antMatchers("/logout").permitAll()
                .antMatchers("/products*").hasRole("user").anyRequest().permitAll();
    }

}


