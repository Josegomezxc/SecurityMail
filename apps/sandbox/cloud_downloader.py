"""
Descarga archivos desde URLs de cloud storage (Google Drive, Dropbox)
y los devuelve como (filename, bytes) para que el sandbox los analice.

Variables de entorno necesarias:
  GOOGLE_DRIVE_SERVICE_ACCOUNT (opcional) — JSON de la service account.
    Si no está configurada, se usa descarga directa (solo archivos públicos).
"""

import os
import re
import requests
from typing import Optional

TIMEOUT        = 30
MAX_FILE_SIZE  = 250 * 1024 * 1024  # 250 MB

PROVIDER_PATTERNS = [
    (re.compile(r'drive\.google\.com/file/d/([^/?#&]+)'),    'gdrive'),
    (re.compile(r'drive\.google\.com/uc\?.*[&?]id=([^&]+)'), 'gdrive'),
    (re.compile(r'drive\.google\.com/open\?id=([^&]+)'),     'gdrive'),
    (re.compile(r'dropbox\.com/s/([a-z0-9]+)/(.+)'),         'dropbox'),
    (re.compile(r'dropbox\.com/scl/fi/([a-zA-Z0-9_-]+)/(.+)'), 'dropbox'),
]


def download_from_urls(urls: list) -> list:
    """Recibe lista de URLs del cuerpo del email.
    Devuelve [(filename, bytes), ...] descargados desde cloud storage."""
    results = []

    for url in urls:
        for pattern, provider in PROVIDER_PATTERNS:
            m = pattern.search(url)
            if not m:
                continue

            try:
                result = None
                if provider == 'gdrive':
                    file_id = m.group(1)
                    try:
                        result = _gdrive_download_api(file_id)
                    except Exception:
                        result = _gdrive_download_direct(file_id)

                elif provider == 'dropbox':
                    file_id = m.group(1)
                    fname = m.group(2)
                    result = _dropbox_download(file_id, fname)

                if result:
                    fname, data = result
                    results.append((f"[cloud]_{fname}", data))
                    print(f"[cloud_downloader] descargado: {fname} ({len(data)//1024} KB)")

            except Exception as e:
                print(f"[cloud_downloader] error en {url[:60]}: {e}")

            break

    return results


def _get_gdrive_service():
    """Crea cliente autenticado para Google Drive API v3 con service account."""
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    creds_json = os.environ.get('GOOGLE_DRIVE_SERVICE_ACCOUNT')
    if not creds_json:
        raise RuntimeError("GOOGLE_DRIVE_SERVICE_ACCOUNT no configurada")

    import json
    creds_dict = json.loads(creds_json)
    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=['https://www.googleapis.com/auth/drive.readonly'],
    )
    return build('drive', 'v3', credentials=credentials, cache_discovery=False)


def _gdrive_download_api(file_id: str) -> Optional[tuple]:
    """Descarga archivo de Google Drive usando API v3 con service account.
    Devuelve (filename, bytes) o None."""
    from googleapiclient.http import MediaIoBaseDownload
    import io

    service = _get_gdrive_service()

    meta = service.files().get(
        fileId=file_id,
        fields='name, mimeType, size',
        supportsAllDrives=True,
    ).execute()

    fname = meta.get('name', 'gdrive_file')
    size = int(meta.get('size', 0))
    if size > MAX_FILE_SIZE:
        print(f"[cloud_downloader] {fname} excede {MAX_FILE_SIZE//1024//1024}MB")
        return None

    request = service.files().get_media(fileId=file_id, supportsAllDrives=True)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request, chunksize=1024 * 1024)
    done = False
    while not done:
        _, done = downloader.next_chunk()

    return fname, fh.getvalue()


def _gdrive_download_direct(file_id: str) -> Optional[tuple]:
    """Fallback sin API: descarga directa para archivos públicos."""
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    session = requests.Session()
    resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)

    confirm = re.search(r'confirm=([^&]+)', resp.text or resp.url)
    if confirm:
        url += f"&confirm={confirm.group(1)}"
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)

    cd = resp.headers.get('Content-Disposition', '')
    fname = 'gdrive_file'
    if 'filename=' in cd:
        fname = cd.split('filename=')[-1].strip('"\'')

    if len(resp.content) > MAX_FILE_SIZE:
        return None
    return fname, resp.content


def _dropbox_download(file_id: str, filename: str) -> Optional[tuple]:
    """Descarga directa de Dropbox con ?dl=1."""
    url = f"https://www.dropbox.com/s/{file_id}/{filename.split('/')[-1]}?dl=1"
    resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    resp.raise_for_status()

    cd = resp.headers.get('Content-Disposition', '')
    fname = filename.split('/')[-1]
    if 'filename=' in cd:
        fname = cd.split('filename=')[-1].strip('"\'')

    if len(resp.content) > MAX_FILE_SIZE:
        return None
    return fname, resp.content
