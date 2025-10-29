"""External SAST integrations for MobSF."""
from __future__ import annotations

import json
import logging
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from django.conf import settings

from mobsf.MobSF.utils import append_scan_status, upstream_proxy

logger = logging.getLogger(__name__)


def _build_source_bundle(source_root: Path) -> Optional[str]:
    """Create a temporary ZIP archive with the source tree."""
    if not source_root.exists():
        logger.warning('External SAST: source directory %s does not exist', source_root)
        return None
    tmp = tempfile.NamedTemporaryFile(prefix='mobsf_sast_', suffix='.zip', delete=False)
    tmp.close()
    try:
        with zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in source_root.rglob('*'):
                if path.is_file():
                    try:
                        archive.write(path, arcname=path.relative_to(source_root))
                    except ValueError:
                        # Files outside of the root are ignored to avoid path traversal.
                        continue
        return tmp.name
    except Exception:
        logger.exception('External SAST: unable to create source bundle')
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return None


def augment_findings_with_external(findings: Dict[str, Any],
                                   external_results: Iterable[Dict[str, Any]]
                                   ) -> Dict[str, Any]:
    """Attach external integration metadata to rule findings."""
    if not isinstance(findings, dict) or not external_results:
        return findings
    metadata = {}
    core = dict(findings)
    if isinstance(core.get('__metadata__'), dict):
        metadata = dict(core.pop('__metadata__'))
    metadata['external_sast'] = list(external_results)
    core['__metadata__'] = metadata
    return core


class ExternalSASTConnector:
    """Base connector to forward scans to external SAST services."""

    def __init__(
        self,
        *,
        name: str,
        api_url: str,
        api_token: str,
        file_field: str = 'bundle',
        token_header: str = 'Authorization',
        token_prefix: str = 'Bearer ',
        extra_payload: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        include_bundle: bool = True,
    ) -> None:
        self.name = name
        self.api_url = (api_url or '').strip()
        self.api_token = (api_token or '').strip()
        self.file_field = file_field or 'bundle'
        self.token_header = token_header
        self.token_prefix = token_prefix or ''
        self.extra_payload = dict(extra_payload or {})
        self.extra_headers = dict(extra_headers or {})
        self.include_bundle = include_bundle
        self.timeout = getattr(settings, 'SAST_INTEGRATION_TIMEOUT', 120)

    def is_configured(self) -> bool:
        return bool(self.api_url and self.api_token)

    def build_headers(self) -> Dict[str, str]:
        headers = {'Accept': 'application/json'}
        headers.update(self.extra_headers)
        if self.token_header:
            headers[self.token_header] = f'{self.token_prefix}{self.api_token}'
        return headers

    def build_payload(self, checksum: str, source_root: Path) -> Dict[str, Any]:
        payload = {
            'source': 'MobSF',
            'checksum': checksum,
        }
        payload.update(self.extra_payload)
        return payload

    def dispatch(self, checksum: str, source_root: Path,
                 archive_path: Optional[str]) -> Optional[Dict[str, Any]]:
        if not self.is_configured():
            logger.debug('%s integration skipped due to missing configuration', self.name)
            return None
        payload = self.build_payload(checksum, source_root)
        headers = self.build_headers()
        try:
            proxies, verify = upstream_proxy('https')
        except Exception as exp:
            proxies, verify = {}, True
            logger.exception('External SAST: proxy setup failed for %s', self.name)
            append_scan_status(checksum, f'{self.name}: proxy configuration error', repr(exp))
        if self.include_bundle and not archive_path:
            message = f'{self.name}: source bundle unavailable for integration'
            logger.warning('External SAST: %s', message)
            append_scan_status(checksum, message)
            return {
                'provider': self.name,
                'status': 'skipped',
                'message': 'Source bundle unavailable',
                'http_status': None,
                'details': '',
            }
        try:
            if self.include_bundle and archive_path:
                with open(archive_path, 'rb') as archive_fp:
                    files = {
                        self.file_field: (
                            f'{checksum}.zip', archive_fp, 'application/zip')
                    }
                    response = requests.post(
                        self.api_url,
                        data=payload,
                        headers=headers,
                        files=files,
                        timeout=self.timeout,
                        proxies=proxies,
                        verify=verify,
                    )
            else:
                response = requests.post(
                    self.api_url,
                    data=payload,
                    headers=headers,
                    timeout=self.timeout,
                    proxies=proxies,
                    verify=verify,
                )
        except requests.RequestException as exp:
            logger.exception('External SAST: request to %s failed', self.name)
            append_scan_status(checksum, f'{self.name}: request failed', repr(exp))
            return {
                'provider': self.name,
                'status': 'error',
                'message': 'Failed to contact integration endpoint',
                'http_status': None,
                'details': str(exp),
            }
        result = self._summarise_response(response)
        append_scan_status(checksum, f"{self.name}: {result['message']}")
        return result

    def _summarise_response(self, response: requests.Response) -> Dict[str, Any]:
        status = 'submitted' if response.ok else 'error'
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text or ''
        if isinstance(body, dict):
            message = body.get('message') or body.get('detail') or ''
            reference = next(
                (body.get(key) for key in (
                    'url', 'link', 'reference', 'report_url', 'html_url', 'dashboard_url')
                 if body.get(key)),
                None)
            detail_text = json.dumps(body, ensure_ascii=False)
        else:
            message = str(body)
            reference = None
            detail_text = message
        if not message:
            message = f'HTTP {response.status_code}'
        if not reference:
            reference = response.headers.get('Location')
        detail_text = detail_text[:2000]
        return {
            'provider': self.name,
            'status': status,
            'http_status': response.status_code,
            'message': message,
            'reference': reference,
            'details': detail_text,
        }


class SemgrepConnector(ExternalSASTConnector):
    def __init__(self, config: Dict[str, Any]) -> None:
        extra_payload = dict(config.get('extra_payload') or {})
        project = config.get('project_slug')
        if project:
            extra_payload.setdefault('project_slug', project)
        extra_payload.setdefault('triggered_by', 'MobSF')
        super().__init__(
            name='Semgrep',
            api_url=config.get('api_url', ''),
            api_token=config.get('api_token', ''),
            file_field=config.get('file_field', 'bundle'),
            token_header=config.get('token_header', 'Authorization'),
            token_prefix=config.get('token_prefix', 'Bearer '),
            extra_payload=extra_payload,
            include_bundle=config.get('include_bundle', True),
        )


class JitConnector(ExternalSASTConnector):
    def __init__(self, config: Dict[str, Any]) -> None:
        extra_payload = dict(config.get('extra_payload') or {})
        project = config.get('project_id')
        if project:
            extra_payload.setdefault('project_id', project)
        extra_payload.setdefault('source', 'MobSF')
        super().__init__(
            name='Jit.io',
            api_url=config.get('api_url', ''),
            api_token=config.get('api_token', ''),
            file_field=config.get('file_field', 'bundle'),
            token_header=config.get('token_header', 'Authorization'),
            token_prefix=config.get('token_prefix', 'Bearer '),
            extra_payload=extra_payload,
            include_bundle=config.get('include_bundle', True),
        )


class CustomConnector(ExternalSASTConnector):
    def __init__(self, config: Dict[str, Any]) -> None:
        name = config.get('name') or 'Custom SAST'
        extra_payload = config.get('extra_payload')
        extra_headers = config.get('headers')
        super().__init__(
            name=name,
            api_url=config.get('api_url', ''),
            api_token=config.get('api_token', ''),
            file_field=config.get('file_field', 'bundle'),
            token_header=config.get('token_header', 'Authorization'),
            token_prefix=config.get('token_prefix', 'Bearer '),
            extra_payload=extra_payload if isinstance(extra_payload, dict) else None,
            extra_headers=extra_headers if isinstance(extra_headers, dict) else None,
            include_bundle=config.get('include_bundle', True),
        )
        self.enabled = config.get('enabled', True)

    def is_configured(self) -> bool:
        return self.enabled and super().is_configured()


class ExternalSASTDispatcher:
    """Prepare bundles and forward scans to configured connectors."""

    def __init__(self, connectors: Iterable[ExternalSASTConnector]) -> None:
        self.connectors = [c for c in connectors if c.is_configured()]

    @classmethod
    def from_settings(cls) -> 'ExternalSASTDispatcher':
        connectors: List[ExternalSASTConnector] = []
        semgrep_cfg = getattr(settings, 'SEMGREP_INTEGRATION', {})
        if semgrep_cfg.get('enabled') and semgrep_cfg.get('api_token'):
            connectors.append(SemgrepConnector(semgrep_cfg))
        jit_cfg = getattr(settings, 'JIT_INTEGRATION', {})
        if jit_cfg.get('enabled') and jit_cfg.get('api_token'):
            connectors.append(JitConnector(jit_cfg))
        for custom_cfg in getattr(settings, 'GENERIC_SAST_INTEGRATIONS', []) or []:
            if isinstance(custom_cfg, dict) and custom_cfg.get('api_token'):
                connectors.append(CustomConnector(custom_cfg))
        return cls(connectors)

    @property
    def has_connectors(self) -> bool:
        return bool(self.connectors)

    def dispatch(self, checksum: str, source_root: Path) -> List[Dict[str, Any]]:
        if not self.connectors:
            return []
        source_root = source_root.resolve()
        requires_bundle = any(c.include_bundle for c in self.connectors)
        archive_path: Optional[str] = None
        if requires_bundle:
            archive_path = _build_source_bundle(source_root)
            if not archive_path:
                logger.warning('External SAST: failed to prepare archive for %s', source_root)
        append_scan_status(
            checksum,
            f'Triggering {len(self.connectors)} external SAST integration(s)')
        results: List[Dict[str, Any]] = []
        try:
            for connector in self.connectors:
                result = connector.dispatch(checksum, source_root, archive_path)
                if result:
                    results.append(result)
        finally:
            if archive_path and os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                except OSError:
                    pass
        return results


__all__ = [
    'ExternalSASTDispatcher',
    'augment_findings_with_external',
]
