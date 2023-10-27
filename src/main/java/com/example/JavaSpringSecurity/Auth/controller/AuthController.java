package com.example.JavaSpringSecurity.Auth.controller;

import com.example.JavaSpringSecurity.Auth.reponseAndRequest.AuthenticateRequest;
import com.example.JavaSpringSecurity.Auth.reponseAndRequest.AuthenticationResponse;
import com.example.JavaSpringSecurity.Auth.reponseAndRequest.RegisterRequest;
import com.example.JavaSpringSecurity.Auth.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticateRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }
}
