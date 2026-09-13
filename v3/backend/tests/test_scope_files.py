import json

import pytest

from app.scope_files import parse_scope_file, path_is_in_scope, scope_dispatch_error


def test_json_scope_is_normalized_and_signed():
    scope = parse_scope_file(json.dumps({
        "target": "https://app.example.test/",
        "authorization_id": "AUTH-42",
        "authorization_expires_at": "2030-01-01T00:00:00Z",
        "allowed_paths": ["/", "/api"],
        "excluded_paths": ["/logout"],
        "allowed_ports": [443],
        "credential_reference": "vault://engagements/42/test-user",
    }), "scope.json")

    assert scope["target"] == "https://app.example.test"
    assert len(scope["validation_token"]) == 64
    assert path_is_in_scope("https://app.example.test/api/health", scope)
    assert not path_is_in_scope("https://app.example.test/logout", scope)


def test_csv_scope_requires_one_asset_and_target_port():
    content = "target,authorization_id,authorization_expires_at,allowed_paths,allowed_ports\nhttps://app.example.test,AUTH-42,2030-01-01T00:00:00Z,/api,8443\n"
    with pytest.raises(ValueError, match="must include the target URL port"):
        parse_scope_file(content, "scope.csv")


def test_expired_scope_blocks_dispatch():
    scope = parse_scope_file(json.dumps({
        "target": "https://app.example.test",
        "authorization_id": "AUTH-42",
        "authorization_expires_at": "2030-01-01T00:00:00Z",
        "allowed_paths": ["/"],
        "allowed_ports": [443],
    }), "scope.json")
    scope["authorization_expires_at"] = "2020-01-01T00:00:00Z"
    assert scope_dispatch_error(scope, "https://app.example.test") == "Scope authorization has expired"
