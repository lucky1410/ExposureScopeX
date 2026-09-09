"""Database and S3-compatible immutable artifact storage."""

from __future__ import annotations

import hashlib
import tarfile
import tempfile
from pathlib import Path

from app.config import settings


def _client():
    import boto3

    arguments = {
        "endpoint_url": settings.S3_ENDPOINT_URL,
        "region_name": settings.S3_REGION,
    }
    if settings.S3_ACCESS_KEY_ID and settings.S3_SECRET_ACCESS_KEY:
        arguments.update({
            "aws_access_key_id": settings.S3_ACCESS_KEY_ID,
            "aws_secret_access_key": settings.S3_SECRET_ACCESS_KEY,
        })
    return boto3.client(
        "s3",
        **arguments,
    )


def object_key(org_id: str, category: str, identifier: str, filename: str) -> str:
    safe_filename = "".join(char if char.isalnum() or char in "._-" else "_" for char in filename)
    suffix = f"{org_id}/{category}/{identifier}/{safe_filename}"
    prefix = settings.S3_PREFIX.strip("/")
    return f"{prefix}/{suffix}" if prefix else suffix


def put_bytes(key: str, content: bytes, media_type: str) -> None:
    arguments = {
        "Bucket": settings.S3_BUCKET,
        "Key": key,
        "Body": content,
        "ContentType": media_type,
        "Metadata": {"sha256": hashlib.sha256(content).hexdigest()},
    }
    if settings.S3_SERVER_SIDE_ENCRYPTION:
        arguments["ServerSideEncryption"] = settings.S3_SERVER_SIDE_ENCRYPTION
    _client().put_object(**arguments)


def get_bytes(key: str) -> bytes:
    return _client().get_object(Bucket=settings.S3_BUCKET, Key=key)["Body"].read()


def delete_object(key: str | None) -> None:
    if key:
        _client().delete_object(Bucket=settings.S3_BUCKET, Key=key)


def persist_report(org_id: str, report_id: str, filename: str, content: bytes, media_type: str) -> tuple[str, str | None, bytes | None]:
    if settings.ARTIFACT_STORAGE_BACKEND != "s3":
        return "database", None, content
    key = object_key(org_id, "reports", report_id, filename)
    put_bytes(key, content, media_type)
    return "s3", key, None


def load_report(storage_backend: str, key: str | None, content: bytes | None) -> bytes:
    if storage_backend == "s3":
        if not key:
            raise FileNotFoundError("Report object key is missing")
        return get_bytes(key)
    if content is None:
        raise FileNotFoundError("Database report content is missing")
    return content


def archive_scan_directory(org_id: str, scan_id: str, directory: str) -> str | None:
    if settings.ARTIFACT_STORAGE_BACKEND != "s3":
        return None
    root = Path(directory).resolve()
    if not root.is_dir():
        return None
    key = object_key(org_id, "scans", scan_id, "evidence.tar.gz")
    with tempfile.NamedTemporaryFile(prefix="exsx-evidence-", suffix=".tar.gz") as temporary:
        with tarfile.open(fileobj=temporary, mode="w:gz", dereference=False) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    archive.add(path, arcname=path.relative_to(root), recursive=False)
        temporary.flush()
        digest = hashlib.sha256()
        temporary.seek(0)
        while chunk := temporary.read(1024 * 1024):
            digest.update(chunk)
        extra_args = {
            "ContentType": "application/gzip",
            "Metadata": {"sha256": digest.hexdigest()},
        }
        if settings.S3_SERVER_SIDE_ENCRYPTION:
            extra_args["ServerSideEncryption"] = settings.S3_SERVER_SIDE_ENCRYPTION
        _client().upload_file(temporary.name, settings.S3_BUCKET, key, ExtraArgs=extra_args)
    return key
