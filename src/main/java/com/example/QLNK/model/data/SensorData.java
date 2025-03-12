package com.example.QLNK.model.data;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;

@Entity
@Getter
public class SensorData implements DataRecord{

    private Integer data;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

}
