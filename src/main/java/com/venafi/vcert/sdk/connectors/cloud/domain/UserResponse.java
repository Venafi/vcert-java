package com.venafi.vcert.sdk.connectors.cloud.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserResponse {

    private List<User> users;
}
