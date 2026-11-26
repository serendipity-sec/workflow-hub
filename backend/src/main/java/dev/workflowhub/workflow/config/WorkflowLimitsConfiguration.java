package dev.workflowhub.workflow.config;

import dev.workflowhub.workflow.service.WorkflowLimits;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WorkflowLimitsConfiguration {
  @Bean
  WorkflowLimits workflowLimits(
      @Value("${app.workflow-limits.max-depth}") int maxDepth,
      @Value("${app.workflow-limits.max-nodes}") int maxNodes,
      @Value("${app.workflow-limits.max-connections}") int maxConnections) {
    return new WorkflowLimits(maxDepth, maxNodes, maxConnections);
  }
}
