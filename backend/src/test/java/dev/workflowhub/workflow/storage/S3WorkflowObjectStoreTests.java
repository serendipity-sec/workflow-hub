package dev.workflowhub.workflow.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/** mock 클라이언트로 S3 요청 형태만 확인한다. 실제 S3에는 접속하지 않는다. */
class S3WorkflowObjectStoreTests {
  private final S3Client s3 = mock(S3Client.class);

  @Test
  void putsBytesWithoutOverwriting() throws Exception {
    var store = new S3WorkflowObjectStore(s3, "test-bucket");
    byte[] content = "{\"synthetic\":true}".getBytes();

    store.put("workflows/w/v.json", content);

    var request = ArgumentCaptor.forClass(PutObjectRequest.class);
    var body = ArgumentCaptor.forClass(RequestBody.class);
    verify(s3).putObject(request.capture(), body.capture());
    assertThat(request.getValue().bucket()).isEqualTo("test-bucket");
    assertThat(request.getValue().key()).isEqualTo("workflows/w/v.json");
    assertThat(request.getValue().ifNoneMatch()).isEqualTo("*");
    assertThat(request.getValue().contentType()).isEqualTo("application/json");
    assertThat(body.getValue().contentStreamProvider().newStream().readAllBytes())
        .isEqualTo(content);
  }

  @Test
  void deletesByKey() {
    new S3WorkflowObjectStore(s3, "test-bucket").delete("workflows/w/v.json");

    var request = ArgumentCaptor.forClass(DeleteObjectRequest.class);
    verify(s3).deleteObject(request.capture());
    assertThat(request.getValue().bucket()).isEqualTo("test-bucket");
    assertThat(request.getValue().key()).isEqualTo("workflows/w/v.json");
  }

  @Test
  void rejectsABlankBucket() {
    assertThatThrownBy(() -> new S3WorkflowObjectStore(s3, " "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_BUCKET");
    verifyNoInteractions(s3);
  }
}
