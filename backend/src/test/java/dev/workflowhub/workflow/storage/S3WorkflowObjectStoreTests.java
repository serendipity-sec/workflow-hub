package dev.workflowhub.workflow.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

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
  void readsOriginalBytesByKey() {
    byte[] content = "{\n  \"name\": \"합성 예시\"\n}\r\n".getBytes(StandardCharsets.UTF_8);
    when(s3.getObjectAsBytes(any(GetObjectRequest.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), content));

    var store = new S3WorkflowObjectStore(s3, "test-bucket");
    assertThat(store.get("stored/key.json")).isEqualTo(content);

    var request = ArgumentCaptor.forClass(GetObjectRequest.class);
    verify(s3).getObjectAsBytes(request.capture());
    assertThat(request.getValue().bucket()).isEqualTo("test-bucket");
    assertThat(request.getValue().key()).isEqualTo("stored/key.json");
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
  void readsTheSizeWithoutDownloadingTheObject() {
    when(s3.headObject(any(HeadObjectRequest.class)))
        .thenReturn(HeadObjectResponse.builder().contentLength(52L).build());

    var size = new S3WorkflowObjectStore(s3, "test-bucket").size("workflows/w/v.json");

    assertThat(size).hasValue(52L);
    var request = ArgumentCaptor.forClass(HeadObjectRequest.class);
    verify(s3).headObject(request.capture());
    assertThat(request.getValue().bucket()).isEqualTo("test-bucket");
    assertThat(request.getValue().key()).isEqualTo("workflows/w/v.json");
    verify(s3, org.mockito.Mockito.never()).getObjectAsBytes(any(GetObjectRequest.class));
  }

  @Test
  void reportsAMissingObjectAsEmptyOnlyWhenS3SaysItDoesNotExist() {
    var store = new S3WorkflowObjectStore(s3, "test-bucket");
    when(s3.headObject(any(HeadObjectRequest.class)))
        .thenThrow(NoSuchKeyException.builder().statusCode(404).build());
    assertThat(store.size("missing")).isEmpty();

    when(s3.headObject(any(HeadObjectRequest.class)))
        .thenThrow(S3Exception.builder().statusCode(404).build());
    assertThat(store.size("missing")).isEmpty();
  }

  @Test
  void doesNotTreatAnAccessErrorAsAMissingObject() {
    // s3:ListBucket 권한이 없으면 없는 객체도 403이다. 없다고 단정하면 복구할 수 있는 원본을 잃은 것으로 처리된다.
    when(s3.headObject(any(HeadObjectRequest.class)))
        .thenThrow(S3Exception.builder().statusCode(403).build());

    assertThatThrownBy(() -> new S3WorkflowObjectStore(s3, "test-bucket").size("key"))
        .isInstanceOf(S3Exception.class);
  }

  @Test
  void rejectsABlankBucket() {
    assertThatThrownBy(() -> new S3WorkflowObjectStore(s3, " "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_BUCKET");
    verifyNoInteractions(s3);
  }
}
