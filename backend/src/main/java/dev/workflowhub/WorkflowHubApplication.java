package dev.workflowhub;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class WorkflowHubApplication {
  public static void main(String[] args) {
    SpringApplication.run(WorkflowHubApplication.class, args);
  }
}
