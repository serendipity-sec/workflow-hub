package dev.workflowhub.workflow.storage;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

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
  public void delete(String key) {
    s3.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
  }
}
