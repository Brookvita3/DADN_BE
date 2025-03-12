package com.example.QLNK.model.user;

import lombok.Data;

import java.util.List;

@Data
public class Group {
    private String username;
    private String key;
    private String name;
    private String description;
    private List<Feed> feeds;
}
