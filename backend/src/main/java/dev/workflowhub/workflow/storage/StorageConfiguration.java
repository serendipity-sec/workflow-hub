package dev.workflowhub.workflow.storage;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

@Configuration
public class StorageConfiguration {
  /** 자격 증명은 AWS 기본 공급자 체인에서 첫 사용 시 가져온다. 느린 S3가 요청 스레드를 오래 잡지 않도록 시간을 제한한다. */
  @Bean
  S3Client s3Client(
      @Value("${app.storage.region}") String region,
      @Value("${app.storage.attempt-timeout}") Duration attemptTimeout,
      @Value("${app.storage.call-timeout}") Duration callTimeout) {
    return S3Client.builder()
        .region(Region.of(region))
        .overrideConfiguration(
            ClientOverrideConfiguration.builder()
                .apiCallAttemptTimeout(attemptTimeout)
                .apiCallTimeout(callTimeout)
                .build())
        .build();
  }

  /** 버킷이 비어 있으면 생성자가 시작 단계에서 실패시켜, 배포 후 사용자 요청에서야 알게 되는 일을 막는다. */
  @Bean
  WorkflowObjectStore workflowObjectStore(
      S3Client s3Client, @Value("${app.storage.bucket}") String bucket) {
    return new S3WorkflowObjectStore(s3Client, bucket);
  }
}
