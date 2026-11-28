package dev.workflowhub.analysis.config;

import dev.workflowhub.analysis.queue.ScanTaskQueue;
import dev.workflowhub.analysis.queue.SqsScanTaskQueue;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class AnalysisConfiguration {
  @Bean
  SqsClient sqsClient(
      @Value("${app.storage.region}") String region,
      @Value("${app.analysis.queue-attempt-timeout}") Duration attemptTimeout,
      @Value("${app.analysis.queue-call-timeout}") Duration callTimeout) {
    return SqsClient.builder()
        .region(Region.of(region))
        .overrideConfiguration(
            ClientOverrideConfiguration.builder()
                .apiCallAttemptTimeout(attemptTimeout)
                .apiCallTimeout(callTimeout)
                .build())
        .build();
  }

  @Bean
  ScanTaskQueue scanTaskQueue(
      SqsClient sqsClient, @Value("${app.analysis.queue-url}") String queueUrl, JsonMapper mapper) {
    return new SqsScanTaskQueue(sqsClient, queueUrl, mapper);
  }
}
