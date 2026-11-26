package dev.workflowhub.workflow.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;

class StorageConfigurationTests {
  @Test
  void startupFailsWhenTheBucketIsNotConfigured() {
    S3Client s3 = mock(S3Client.class);

    assertThatThrownBy(() -> new StorageConfiguration().workflowObjectStore(s3, ""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_BUCKET");
    verifyNoInteractions(s3);
  }
}
