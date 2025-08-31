package com.example.authmicro.performance;

import com.example.authmicro.dto.LoginRequest;
import com.example.authmicro.dto.UserBodyRequest;
import com.example.authmicro.entity.Role;
import com.example.authmicro.repository.AuthUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebMvc
@ActiveProfiles("test")
@Transactional
@DisplayName("Performance Tests")
class PerformanceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Concurrent user registration should handle load")
    void concurrentUserRegistrationShouldHandleLoad() throws Exception {
        int numberOfUsers = 50;
        int numberOfThreads = 10;
        
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        
        long startTime = System.currentTimeMillis();
        
        CompletableFuture<?>[] futures = IntStream.range(0, numberOfUsers)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    try {
                        UserBodyRequest request = new UserBodyRequest(
                            "user" + i + "@example.com", 
                            "password123", 
                            Role.USER
                        );
                        
                        MvcResult result = mockMvc.perform(post("/signup")
                                .with(csrf())
                                .header("X-API-Key", "test-api-key-secret")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andReturn();
                        
                        assertThat(result.getResponse().getStatus()).isEqualTo(200);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, executor))
                .toArray(CompletableFuture[]::new);
        
        CompletableFuture.allOf(futures).get(30, TimeUnit.SECONDS);
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        // Verify all users were created
        assertThat(userRepository.count()).isEqualTo(numberOfUsers);
        
        // Performance assertion (should complete within 30 seconds)
        assertThat(duration).isLessThan(30000);
        
        System.out.printf("Created %d users in %d ms (%.2f users/second)%n", 
                numberOfUsers, duration, (numberOfUsers * 1000.0) / duration);
        
        executor.shutdown();
    }

    @Test
    @DisplayName("Concurrent login requests should handle load")
    void concurrentLoginRequestsShouldHandleLoad() throws Exception {
        // First create a test user
        UserBodyRequest signupRequest = new UserBodyRequest("loadtest@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        int numberOfRequests = 100;
        int numberOfThreads = 10;
        
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        
        long startTime = System.currentTimeMillis();
        
        CompletableFuture<?>[] futures = IntStream.range(0, numberOfRequests)
                .mapToObj(i -> CompletableFuture.runAsync(() -> {
                    try {
                        LoginRequest request = new LoginRequest("loadtest@example.com", "password123");
                        
                        MvcResult result = mockMvc.perform(post("/login")
                                .with(csrf())
                                .header("X-API-Key", "test-api-key-secret")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andReturn();
                        
                        assertThat(result.getResponse().getStatus()).isEqualTo(200);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, executor))
                .toArray(CompletableFuture[]::new);
        
        CompletableFuture.allOf(futures).get(30, TimeUnit.SECONDS);
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        // Performance assertion
        assertThat(duration).isLessThan(30000);
        
        System.out.printf("Completed %d login requests in %d ms (%.2f requests/second)%n", 
                numberOfRequests, duration, (numberOfRequests * 1000.0) / duration);
        
        executor.shutdown();
    }

    @Test
    @DisplayName("Memory usage should remain stable under load")
    void memoryUsageShouldRemainStableUnderLoad() throws Exception {
        Runtime runtime = Runtime.getRuntime();
        
        // Force garbage collection and measure initial memory
        runtime.gc();
        long initialMemory = runtime.totalMemory() - runtime.freeMemory();
        
        // Create many users to test memory usage
        int numberOfUsers = 100;
        
        for (int i = 0; i < numberOfUsers; i++) {
            UserBodyRequest request = new UserBodyRequest(
                "memtest" + i + "@example.com", 
                "password123", 
                Role.USER
            );
            
            mockMvc.perform(post("/signup")
                    .with(csrf())
                    .header("X-API-Key", "test-api-key-secret")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());
        }
        
        // Force garbage collection and measure final memory
        runtime.gc();
        long finalMemory = runtime.totalMemory() - runtime.freeMemory();
        
        long memoryIncrease = finalMemory - initialMemory;
        
        System.out.printf("Memory usage increased by %d bytes (%.2f MB) for %d users%n", 
                memoryIncrease, memoryIncrease / 1024.0 / 1024.0, numberOfUsers);
        
        // Assert memory increase is reasonable (less than 50MB for 100 users)
        assertThat(memoryIncrease).isLessThan(50 * 1024 * 1024);
    }

    @Test
    @DisplayName("JWT token generation should be fast")
    void jwtTokenGenerationShouldBeFast() throws Exception {
        // Create test user
        UserBodyRequest signupRequest = new UserBodyRequest("jwttest@example.com", "password123", Role.USER);
        mockMvc.perform(post("/signup")
                .with(csrf())
                .header("X-API-Key", "test-api-key-secret")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk());

        int numberOfLogins = 1000;
        LoginRequest loginRequest = new LoginRequest("jwttest@example.com", "password123");
        
        long startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfLogins; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .header("X-API-Key", "test-api-key-secret")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginRequest)))
                    .andExpect(status().isOk());
        }
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        double averageTime = (double) duration / numberOfLogins;
        
        System.out.printf("Generated %d JWT tokens in %d ms (average: %.2f ms/token)%n", 
                numberOfLogins, duration, averageTime);
        
        // Assert average token generation time is reasonable (less than 10ms per token)
        assertThat(averageTime).isLessThan(10.0);
    }
}
