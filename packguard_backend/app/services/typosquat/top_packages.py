"""Cached list of trusted top PyPI package names for typosquat detection."""

from __future__ import annotations

from functools import lru_cache
from typing import Set

# Representative subset of top-5000 PyPI packages. In production, load from
# a cached JSON file refreshed weekly from PyPI download stats.
_TOP_PACKAGES: Set[str] = {
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "numpy", "pandas", "scipy", "matplotlib", "pillow", "flask", "django",
    "fastapi", "uvicorn", "pydantic", "sqlalchemy", "pytest", "setuptools",
    "wheel", "pip", "boto3", "botocore", "click", "jinja2", "markupsafe",
    "werkzeug", "cryptography", "pyyaml", "six", "python-dateutil", "pytz",
    "typing-extensions", "packaging", "attrs", "cffi", "pycparser",
    "greenlet", "aiohttp", "httpx", "anyio", "sniffio", "h11", "starlette",
    "redis", "celery", "kombu", "billiard", "vine", "amqp", "lxml",
    "beautifulsoup4", "soupsieve", "scrapy", "twisted", "zope-interface",
    "pyopenssl", "paramiko", "bcrypt", "passlib", "jwt", "pyjwt",
    "google-auth", "google-api-core", "protobuf", "grpcio", "tensorflow",
    "torch", "transformers", "huggingface-hub", "tokenizers", "safetensors",
    "scikit-learn", "joblib", "threadpoolctl", "openpyxl", "xlrd",
    "xlsxwriter", "reportlab", "weasyprint", "tinycss2", "cssselect2",
    "pydantic-settings", "python-multipart", "firebase-admin",
    "google-cloud-firestore", "google-cloud-storage", "rapidfuzz",
    "python-levenshtein", "bandit", "astroid", "black", "mypy", "ruff",
    "tqdm", "rich", "colorama", "psutil", "watchdog", "filelock",
    "toml", "tomli", "tomlkit", "platformdirs", "pathspec", "distlib",
    "virtualenv", "poetry", "pipenv", "hatchling", "build", "meson",
    "cython", "numba", "llvmlite", "sympy", "mpmath", "networkx",
    "seaborn", "plotly", "bokeh", "altair", "dash", "streamlit",
    "gradio", "langchain", "openai", "anthropic", "tiktoken",
    "sentencepiece", "nltk", "spacy", "gensim", "textblob", "regex",
    "chardet", "defusedxml", "xmltodict", "orjson", "ujson", "msgpack",
    "pymongo", "motor", "psycopg2-binary", "asyncpg", "aiosqlite",
    "alembic", "peewee", "tortoise-orm", "django-rest-framework",
    "djangorestframework", "gunicorn", "waitress", "gevent", "eventlet",
    "sentry-sdk", "structlog", "loguru", "python-json-logger",
}


@lru_cache
def get_trusted_packages() -> frozenset[str]:
    return frozenset(name.lower() for name in _TOP_PACKAGES)
