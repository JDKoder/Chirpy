-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at) VALUES (
	$1,
	NOW(),
	NOW(),
	$2,
	$3,
	NULL
) RETURNING *;


-- name: RevokeToken :exec
UPDATE refresh_tokens SET updated_at=NOW(), revoked_at=NOW() where token=$1;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens where token=$1 LIMIT(1);

