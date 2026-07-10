"""Rewrite settings secrets to field-level encrypted JSON.

LLM profiles used to be stored as whole-column encrypted JSON. Agent settings
JSON could also contain plaintext secret leaves from legacy saves. Rewrite those
payloads so non-secret JSON remains inspectable while secret leaf fields are
Fernet-encrypted by the settings cipher.

Revision ID: 137
Revises: 136
Create Date: 2026-07-03
"""

import copy
import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Sequence, Union

import sqlalchemy as sa
from alembic import op
from pydantic import SecretStr

revision: str = '137'
down_revision: Union[str, None] = '136'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FERNET_TOKEN_PREFIX = 'gAAAA'
_LLM_SECRET_KEYS = {
    'api_key',
    'aws_access_key_id',
    'aws_secret_access_key',
    'aws_session_token',
}


def upgrade() -> None:
    bind = op.get_bind()
    _rewrite_single_pk_column(bind, 'user', 'id', 'llm_profiles', _profiles_to_json)
    _rewrite_single_pk_column(bind, 'org', 'id', 'llm_profiles', _profiles_to_json)
    _rewrite_single_pk_column(
        bind, 'user_settings', 'id', 'agent_settings', _encrypt_agent_settings
    )
    _rewrite_single_pk_column(
        bind, 'org', 'id', 'agent_settings', _encrypt_agent_settings
    )
    _rewrite_composite_pk_column(
        bind,
        'org_member',
        ('org_id', 'user_id'),
        'agent_settings_diff',
        _encrypt_agent_settings,
    )


def downgrade() -> None:
    bind = op.get_bind()
    _rewrite_single_pk_column(
        bind, 'user', 'id', 'llm_profiles', _profiles_to_encrypted_blob
    )
    _rewrite_single_pk_column(
        bind, 'org', 'id', 'llm_profiles', _profiles_to_encrypted_blob
    )
    _rewrite_single_pk_column(
        bind, 'user_settings', 'id', 'agent_settings', _decrypt_agent_settings
    )
    _rewrite_single_pk_column(
        bind, 'org', 'id', 'agent_settings', _decrypt_agent_settings
    )
    _rewrite_composite_pk_column(
        bind,
        'org_member',
        ('org_id', 'user_id'),
        'agent_settings_diff',
        _decrypt_agent_settings,
    )


def _rewrite_single_pk_column(
    bind,
    table_name: str,
    pk_name: str,
    column_name: str,
    transform: Callable[[Any], Any],
) -> None:
    table = sa.table(table_name, sa.column(pk_name), sa.column(column_name))
    rows = bind.execute(sa.select(table.c[pk_name], table.c[column_name])).mappings()
    for row in rows:
        current = row[column_name]
        updated = transform(current)
        if updated == current:
            continue
        bind.execute(
            table.update()
            .where(table.c[pk_name] == row[pk_name])
            .values({column_name: updated})
        )


def _rewrite_composite_pk_column(
    bind,
    table_name: str,
    pk_names: Iterable[str],
    column_name: str,
    transform: Callable[[Any], Any],
) -> None:
    columns = [sa.column(pk_name) for pk_name in pk_names]
    table = sa.table(table_name, *columns, sa.column(column_name))
    rows = bind.execute(
        sa.select(*(table.c[pk_name] for pk_name in pk_names), table.c[column_name])
    ).mappings()
    for row in rows:
        current = row[column_name]
        updated = transform(current)
        if updated == current:
            continue
        query = table.update()
        for pk_name in pk_names:
            query = query.where(table.c[pk_name] == row[pk_name])
        bind.execute(query.values({column_name: updated}))


def _profiles_to_json(value: Any) -> str | None:
    data = _load_profile_payload(value)
    if data is None:
        return None
    return json.dumps(_encrypt_llm_profile_secrets(data))


def _profiles_to_encrypted_blob(value: Any) -> str | None:
    data = _load_profile_payload(value)
    if data is None:
        return None
    from storage.encrypt_utils import encrypt_value

    return encrypt_value(json.dumps(_decrypt_llm_profile_secrets(data)))


def _load_profile_payload(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str):
        return value
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        from storage.encrypt_utils import decrypt_value

        loaded = json.loads(decrypt_value(value))
    return loaded if isinstance(loaded, dict) else None


def _encrypt_agent_settings(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    data = copy.deepcopy(value)
    _encrypt_llm_secrets(data.get('llm'))
    _encrypt_verification_secrets(data.get('verification'))
    _encrypt_agent_context_secrets(data.get('agent_context'))
    _encrypt_mcp_config_secrets(data.get('mcp_config'))
    return data


def _decrypt_agent_settings(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    data = copy.deepcopy(value)
    _decrypt_llm_secrets(data.get('llm'))
    _decrypt_verification_secrets(data.get('verification'))
    _decrypt_agent_context_secrets(data.get('agent_context'))
    _decrypt_mcp_config_secrets(data.get('mcp_config'))
    return data


def _encrypt_llm_profile_secrets(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.get('profiles')
    if not isinstance(profiles, dict):
        return data
    updated = copy.deepcopy(data)
    for profile in updated.get('profiles', {}).values():
        _encrypt_llm_secrets(profile)
    return updated


def _decrypt_llm_profile_secrets(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.get('profiles')
    if not isinstance(profiles, dict):
        return data
    updated = copy.deepcopy(data)
    for profile in updated.get('profiles', {}).values():
        _decrypt_llm_secrets(profile)
    return updated


def _encrypt_llm_secrets(llm: Any) -> None:
    if not isinstance(llm, dict):
        return
    for key in _LLM_SECRET_KEYS:
        if key in llm:
            llm[key] = _encrypt_secret_value(llm[key])


def _decrypt_llm_secrets(llm: Any) -> None:
    if not isinstance(llm, dict):
        return
    for key in _LLM_SECRET_KEYS:
        if key in llm:
            llm[key] = _decrypt_secret_value(llm[key])


def _encrypt_verification_secrets(verification: Any) -> None:
    if isinstance(verification, dict) and 'critic_api_key' in verification:
        verification['critic_api_key'] = _encrypt_secret_value(
            verification['critic_api_key']
        )


def _decrypt_verification_secrets(verification: Any) -> None:
    if isinstance(verification, dict) and 'critic_api_key' in verification:
        verification['critic_api_key'] = _decrypt_secret_value(
            verification['critic_api_key']
        )


def _encrypt_agent_context_secrets(agent_context: Any) -> None:
    _transform_agent_context_secrets(agent_context, _encrypt_secret_value)


def _decrypt_agent_context_secrets(agent_context: Any) -> None:
    _transform_agent_context_secrets(agent_context, _decrypt_secret_value)


def _transform_agent_context_secrets(
    agent_context: Any, transform: Callable[[Any], Any]
) -> None:
    if not isinstance(agent_context, dict):
        return
    secrets = agent_context.get('secrets')
    if not isinstance(secrets, dict):
        return
    for key, value in list(secrets.items()):
        if isinstance(value, str):
            secrets[key] = transform(value)


def _encrypt_mcp_config_secrets(mcp_config: Any) -> None:
    _transform_mcp_config_secrets(mcp_config, _encrypt_secret_value)


def _decrypt_mcp_config_secrets(mcp_config: Any) -> None:
    _transform_mcp_config_secrets(mcp_config, _decrypt_secret_value)


def _transform_mcp_config_secrets(
    mcp_config: Any, transform: Callable[[Any], Any]
) -> None:
    if not isinstance(mcp_config, dict):
        return
    servers = mcp_config.get('mcpServers')
    if not isinstance(servers, dict):
        return
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        for field in ('env', 'headers'):
            values = server.get(field)
            if not isinstance(values, dict):
                continue
            for key, value in list(values.items()):
                if isinstance(value, str):
                    values[key] = transform(value)


def _encrypt_secret_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    from storage.encrypt_utils import get_settings_cipher

    cipher = get_settings_cipher()
    if (
        value.startswith(_FERNET_TOKEN_PREFIX)
        and cipher.try_decrypt_str(value) is not None
    ):
        return value
    return cipher.encrypt(SecretStr(value))


def _decrypt_secret_value(value: Any) -> Any:
    if not isinstance(value, str) or not value.startswith(_FERNET_TOKEN_PREFIX):
        return value
    from storage.encrypt_utils import get_settings_cipher

    decrypted = get_settings_cipher().try_decrypt_str(value)
    return decrypted if decrypted is not None else value
