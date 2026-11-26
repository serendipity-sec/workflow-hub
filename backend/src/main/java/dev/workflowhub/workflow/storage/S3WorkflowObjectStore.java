package dev.workflowhub.workflow.storage;

import java.util.OptionalLong;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

public class S3WorkflowObjectStore implements WorkflowObjectStore {
  private final S3Client s3;
  private final String bucket;

  public S3WorkflowObjectStore(S3Client s3, String bucket) {
    if (bucket == null || bucket.isBlank()) {
      throw new IllegalArgumentException("WORKFLOW_BUCKET must be set");
    }
    this.s3 = s3;
    this.bucket = bucket;
  }

  @Override
  public void put(String key, byte[] content) {
    s3.putObject(
        PutObjectRequest.builder()
            .bucket(bucket)
            .key(key)
            .contentType("application/json")
            // 같은 키가 있으면 덮어쓰지 않고 412로 실패한다.
            .ifNoneMatch("*")
            .build(),
        RequestBody.fromBytes(content));
  }

  @Override
  public byte[] get(String key) {
    return s3.getObjectAsBytes(GetObjectRequest.builder().bucket(bucket).key(key).build())
        .asByteArray();
  }

  @Override
  public OptionalLong size(String key) {
    try {
      Long length =
          s3.headObject(HeadObjectRequest.builder().bucket(bucket).key(key).build())
              .contentLength();
      if (length == null) {
        throw new IllegalStateException("S3 did not report the object size");
      }
      return OptionalLong.of(length);
    } catch (NoSuchKeyException e) {
      return OptionalLong.empty();
    } catch (S3Exception e) {
      if (e.statusCode() == 404) {
        return OptionalLong.empty();
      }
      // s3:ListBucket 권한이 없으면 없는 객체도 403으로 응답한다. 없다고 단정하지 않고 오류로 올린다.
      throw e;
    }
  }

  @Override
  public void delete(String key) {
    s3.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
  }
}
