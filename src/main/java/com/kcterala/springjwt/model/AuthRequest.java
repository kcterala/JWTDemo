package com.kcterala.springjwt.model;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}
