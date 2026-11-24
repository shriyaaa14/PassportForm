"""Upload a local file to an S3 bucket.

Install dependencies with ``python -m pip install -r requirements.txt``.
Configure AWS credentials for boto3 and set DB_HOST, DB_USER, and DB_PASSWORD
for the MySQL RDS connection. DB_NAME defaults to ``PassportForm`` and DB_PORT
defaults to 3306.
Run ``authentication.sql`` once against the database before serving the app.

In PowerShell, set the connection values before starting the server:
    $env:DB_HOST = "your-rds-endpoint"
    $env:DB_NAME = "PassportForm"
    $env:DB_USER = "your-database-user"
    $env:DB_PASSWORD = "your-database-password"

If needed, run this SQL in MySQL Workbench to allow full S3 paths:
    ALTER TABLE passport_form MODIFY bucket TEXT NOT NULL;

Example:
    python FileCapturer.py "C:\\path\\to\\file.csv" my-bucket --key uploads/file.csv
    python FileCapturer.py --serve --bucket my-bucket --region us-east-1
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from datetime import date
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

import boto3
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import BotoCoreError, ClientError
import mysql.connector
from mysql.connector import Error as MySQLError

MAX_UPLOAD_SIZE = 100 * 1024 * 1024
RDS_TABLE = "passport_form"
RDS_BUCKET_COLUMN = "bucket"
AUTH_TABLE = "authentication"
PASSWORD_HASH_ITERATIONS = 600_000
MIN_PASSWORD_COLUMN_LENGTH = 100
SESSION_DURATION_SECONDS = 8 * 60 * 60
MIN_PASSWORD_LENGTH = 8


@dataclass(frozen=True)
class UploadResult:
    s3_uri: str
    rds_warning: Optional[str] = None


@dataclass(frozen=True)
class PassportDetails:
    first_name: str
    last_name: str
    date_of_birth: str
    nationality: str
    passport_number: str
    issue_date: str
    expiry_date: str
    place_of_issue: str


def validate_passport_details(details: PassportDetails) -> PassportDetails:
    """Validate form values against the passport_form column constraints."""
    limits = {
        "first_name": 50,
        "last_name": 50,
        "nationality": 50,
        "passport_number": 20,
        "place_of_issue": 100,
    }
    normalized = {
        field: getattr(details, field).strip()
        for field in (
            "first_name",
            "last_name",
            "date_of_birth",
            "nationality",
            "passport_number",
            "issue_date",
            "expiry_date",
            "place_of_issue",
        )
    }
    for field, limit in limits.items():
        value = normalized[field]
        if not value:
            raise ValueError(f"{field.replace('_', ' ').capitalize()} is required.")
        if len(value) > limit:
            raise ValueError(f"{field.replace('_', ' ').capitalize()} must be {limit} characters or fewer.")

    try:
        date.fromisoformat(normalized["date_of_birth"])
        issue_date = date.fromisoformat(normalized["issue_date"])
        expiry_date = date.fromisoformat(normalized["expiry_date"])
    except ValueError as exc:
        raise ValueError("Enter valid dates for date of birth, issue date, and expiry date.") from exc
    if expiry_date <= issue_date:
        raise ValueError("Passport expiry date must be after its issue date.")
    return PassportDetails(**normalized)


def rds_connection_options() -> dict[str, str | int]:
    """Read and validate the MySQL RDS connection settings."""
    host = os.environ.get("DB_HOST", "database-1.cfua6wqcare8.ap-southeast-2.rds.amazonaws.com")
    user = os.environ.get("DB_USER","admin")
    password = os.environ.get("DB_PASSWORD","14259n491S")
    if not host or not user or not password:
        missing = [
            name
            for name, value in (("DB_HOST", host), ("DB_USER", user), ("DB_PASSWORD", password))
            if not value
        ]
        raise ValueError(f"Missing required RDS environment variables: {', '.join(missing)}")

    options: dict[str, str | int] = {
        "host": host,
        "port": int(os.environ.get("DB_PORT", "3306")),
        "database": os.environ.get("DB_NAME", "PassportForm"),
        "user": user,
        "password": password,
    }
    ssl_ca = os.environ.get("DB_SSL_CA")
    if ssl_ca:
        options["ssl_ca"] = ssl_ca
        options["ssl_verify_cert"] = True
    return options


def validate_credentials(username: str, password: str) -> tuple[str, str]:
    """Normalize and validate credentials before using them."""
    username = username.strip()
    if not username:
        raise ValueError("Username is required.")
    if len(username) > 100:
        raise ValueError("Username must be 100 characters or fewer.")
    if not password:
        raise ValueError("Password is required.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 1024:
        raise ValueError("Password must be 1024 characters or fewer.")
    return username, password


def hash_password(password: str) -> str:
    """Create a salted PBKDF2 hash suitable for the authentication.password column."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt_text}${digest_text}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Check a password against the encoded hash without revealing comparison timing."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    try:
        algorithm, iterations_text, salt_text, digest_text = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if not 1 <= iterations <= PASSWORD_HASH_ITERATIONS:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, binascii.Error):
        return False


def validate_auth_password_column(cursor, required_length: int) -> None:
    """Reject numeric or undersized password columns before MySQL can coerce a hash."""
    cursor.execute(
        """
        SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND COLUMN_NAME = 'password'
        """,
        (AUTH_TABLE,),
    )
    column = cursor.fetchone()
    if column is None:
        raise RuntimeError(f"Column {AUTH_TABLE}.password was not found in the selected database.")

    data_type, max_length = column
    if data_type.lower() not in {"char", "varchar", "tinytext", "text", "mediumtext", "longtext"}:
        raise RuntimeError(
            f"{AUTH_TABLE}.password must be a character column, not {data_type}. "
            "Run authentication.sql to change it to VARCHAR(255)."
        )
    if max_length is not None and max_length < required_length:
        raise RuntimeError(
            f"{AUTH_TABLE}.password must hold at least {required_length} characters. "
            "Run authentication.sql to change it to VARCHAR(255)."
        )


def create_auth_user(
    username: str,
    password: str,
    connection_options: dict[str, str | int],
) -> None:
    """Store a new username and salted password hash in the authentication table."""
    username, password = validate_credentials(username, password)
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor()
        try:
            password_hash = hash_password(password)
            validate_auth_password_column(cursor, len(password_hash))
            cursor.execute(
                f"INSERT INTO `{AUTH_TABLE}` (`username`, `password`) VALUES (%s, %s)",
                (username, password_hash),
            )
            connection.commit()
        finally:
            cursor.close()
    except MySQLError as exc:
        if connection is not None and connection.is_connected():
            connection.rollback()
        if exc.errno == 1062:
            raise ValueError("That username is already registered.") from exc
        raise
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def authenticate_user(
    username: str,
    password: str,
    connection_options: dict[str, str | int],
) -> bool:
    """Return whether the authentication table contains matching credentials."""
    username = username.strip()
    if not username:
        raise ValueError("Username is required.")
    if len(username) > 100:
        raise ValueError("Username must be 100 characters or fewer.")
    if not password or len(password) > 1024:
        raise ValueError("Password is required.")
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor()
        try:
            validate_auth_password_column(cursor, MIN_PASSWORD_COLUMN_LENGTH)
            cursor.execute(
                f"SELECT `password` FROM `{AUTH_TABLE}` WHERE `username` = %s LIMIT 1",
                (username,),
            )
            row = cursor.fetchone()
            return (
                row is not None
                and isinstance(row[0], str)
                and verify_password(password, row[0])
            )
        finally:
            cursor.close()
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def store_passport_record(
    details: PassportDetails,
    s3_uri: str,
    connection_options: dict[str, str | int],
) -> None:
    """Insert passport details and the full S3 object URI into MySQL RDS."""
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT CHARACTER_MAXIMUM_LENGTH
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_NAME = %s
                """,
                (RDS_TABLE, RDS_BUCKET_COLUMN),
            )
            column = cursor.fetchone()
            if column is None:
                raise RuntimeError(
                    f"Column {RDS_TABLE}.{RDS_BUCKET_COLUMN} was not found in the selected database."
                )
            max_length = column[0]
            if max_length is not None and len(s3_uri) > max_length:
                raise RuntimeError(
                    f"The {RDS_TABLE}.{RDS_BUCKET_COLUMN} column holds at most {max_length} "
                    f"characters, but this S3 path needs {len(s3_uri)}. "
                    "Change the column to TEXT, then retry."
                )

            cursor.execute(
                """
                SELECT COLUMN_NAME, EXTRA
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_KEY = 'PRI'
                """,
                (RDS_TABLE,),
            )
            primary_key_columns = cursor.fetchall()
            non_auto_increment_keys = [
                column_name
                for column_name, extra in primary_key_columns
                if column_name != RDS_BUCKET_COLUMN and "auto_increment" not in extra.lower()
            ]
            if non_auto_increment_keys:
                raise RuntimeError(
                    f"Primary key column(s) {', '.join(non_auto_increment_keys)} in "
                    f"{RDS_TABLE} do not use AUTO_INCREMENT. MySQL may assign duplicate "
                    "default values when inserting only the S3 path. Configure a generated "
                    "primary key in the table, then retry."
                )

            cursor.execute(
                f"""
                INSERT INTO `{RDS_TABLE}`
                    (`first_name`, `last_name`, `date_of_birth`, `nationality`,
                     `passport_number`, `issue_date`, `expiry_date`, `place_of_issue`,
                     `{RDS_BUCKET_COLUMN}`)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    details.first_name,
                    details.last_name,
                    details.date_of_birth,
                    details.nationality,
                    details.passport_number,
                    details.issue_date,
                    details.expiry_date,
                    details.place_of_issue,
                    s3_uri,
                ),
            )
            connection.commit()
        finally:
            cursor.close()
    except MySQLError as exc:
        if connection is not None and connection.is_connected():
            connection.rollback()
        if exc.errno == 1062:
            raise RuntimeError(
                f"S3 upload succeeded for {s3_uri!r}, but the RDS insert hit a duplicate "
                "primary key. Make the table's generated ID primary key AUTO_INCREMENT, "
                "or provide a unique value for its primary key."
            ) from exc
        raise RuntimeError(
            f"S3 upload succeeded for {s3_uri!r}, but recording its path in RDS failed: {exc}"
        ) from exc
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def fetch_passport_records(
    connection_options: dict[str, str | int],
) -> tuple[list[str], list[dict[str, object]], list[str]]:
    """Fetch every passport_form column and row from MySQL RDS."""
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_KEY = 'PRI'
                ORDER BY ORDINAL_POSITION
                """,
                (RDS_TABLE,),
            )
            primary_keys = [column["COLUMN_NAME"] for column in cursor.fetchall()]
            cursor.execute(f"SELECT * FROM `{RDS_TABLE}`")
            columns = [column[0] for column in cursor.description]
            records = cursor.fetchall()
            return columns, records, primary_keys
        finally:
            cursor.close()
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def validate_record_updates(values: dict[str, object]) -> dict[str, object]:
    """Validate passport fields before updating a database record."""
    passport_fields = tuple(PassportDetails.__dataclass_fields__)
    if all(field in values for field in passport_fields):
        details = validate_passport_details(
            PassportDetails(**{field: str(values[field]) for field in passport_fields})
        )
        values = {**values, **details.__dict__}

    if not values:
        raise ValueError("At least one field must be provided for update.")
    if any(value is not None and not isinstance(value, str) for value in values.values()):
        raise ValueError("Updated field values must be text or null.")
    return values


def update_passport_record(
    key: dict[str, object],
    values: dict[str, object],
    connection_options: dict[str, str | int],
) -> None:
    """Update non-primary-key fields for one passport_form record."""
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COLUMN_NAME, COLUMN_KEY
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
                """,
                (RDS_TABLE,),
            )
            schema = cursor.fetchall()
            if not schema:
                raise RuntimeError(f"Table {RDS_TABLE} was not found in the selected database.")

            columns = {column_name for column_name, _ in schema}
            primary_keys = [column_name for column_name, key_type in schema if key_type == "PRI"]
            if not primary_keys:
                raise RuntimeError(f"Table {RDS_TABLE} must have a primary key to edit records.")
            if set(key) != set(primary_keys):
                raise ValueError("The record identifier is incomplete or invalid.")
            if any(not isinstance(value, (str, int, float)) for value in key.values()):
                raise ValueError("Primary key values must be text or numeric.")

            unknown_columns = set(values) - columns
            if unknown_columns:
                raise ValueError(f"Unknown database column(s): {', '.join(sorted(unknown_columns))}.")
            if set(values) & set(primary_keys):
                raise ValueError("Primary key columns cannot be changed.")
            if not values:
                raise ValueError("At least one field must be provided for update.")

            quote_identifier = lambda name: f"`{name.replace('`', '``')}`"
            where_clause = " AND ".join(
                f"{quote_identifier(column)} = %s" for column in primary_keys
            )
            cursor.execute(
                f"SELECT 1 FROM `{RDS_TABLE}` WHERE {where_clause} LIMIT 1",
                tuple(key[column] for column in primary_keys),
            )
            if cursor.fetchone() is None:
                raise LookupError("The selected passport record no longer exists.")

            assignments = ", ".join(
                f"{quote_identifier(column)} = %s" for column in values
            )
            cursor.execute(
                f"UPDATE `{RDS_TABLE}` SET {assignments} WHERE {where_clause}",
                tuple(values.values()) + tuple(key[column] for column in primary_keys),
            )
            connection.commit()
        finally:
            cursor.close()
    except MySQLError:
        if connection is not None and connection.is_connected():
            connection.rollback()
        raise
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def delete_passport_record(
    key: dict[str, object],
    connection_options: dict[str, str | int],
) -> None:
    """Delete exactly one passport_form record by its primary key."""
    connection = None
    try:
        connection = mysql.connector.connect(**connection_options)
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_KEY = 'PRI'
                ORDER BY ORDINAL_POSITION
                """,
                (RDS_TABLE,),
            )
            primary_keys = [column[0] for column in cursor.fetchall()]
            if not primary_keys:
                raise RuntimeError(f"Table {RDS_TABLE} must have a primary key to delete records.")
            if set(key) != set(primary_keys):
                raise ValueError("The record identifier is incomplete or invalid.")
            if any(not isinstance(value, (str, int, float)) for value in key.values()):
                raise ValueError("Primary key values must be text or numeric.")

            where_clause = " AND ".join(f"`{column.replace('`', '``')}` = %s" for column in primary_keys)
            cursor.execute(
                f"DELETE FROM `{RDS_TABLE}` WHERE {where_clause}",
                tuple(key[column] for column in primary_keys),
            )
            if cursor.rowcount == 0:
                raise LookupError("The selected passport record no longer exists.")
            connection.commit()
        finally:
            cursor.close()
    except MySQLError:
        if connection is not None and connection.is_connected():
            connection.rollback()
        raise
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


def upload_file(
    file_path: Path,
    bucket: str,
    object_key: Optional[str] = None,
    region: Optional[str] = None,
    passport_details: Optional[PassportDetails] = None,
) -> UploadResult:
    """Upload to S3, then record passport details and the object URI in RDS."""
    if not file_path.is_file():
        raise FileNotFoundError(f"File does not exist: {file_path}")
    if not bucket:
        raise ValueError("An S3 bucket name is required.")
    if passport_details is not None:
        passport_details = validate_passport_details(passport_details)

    key = object_key or file_path.name
    try:
        s3 = boto3.client("s3", region_name=region)
        s3.upload_file(str(file_path), bucket, key)
    except (BotoCoreError, ClientError, S3UploadFailedError) as exc:
        raise RuntimeError(f"Could not upload to s3://{bucket}/{key}: {exc}") from exc

    s3_uri = f"s3://{bucket}/{key}"
    if passport_details is None:
        return UploadResult(
            s3_uri=s3_uri,
            rds_warning="No passport details were supplied; the S3 path was not recorded in RDS.",
        )
    try:
        store_passport_record(passport_details, s3_uri, rds_connection_options())
    except (RuntimeError, ValueError) as exc:
        warning = f"File uploaded to S3, but its S3 path was not recorded in RDS: {exc}"
        logging.warning(warning)
        return UploadResult(s3_uri=s3_uri, rds_warning=warning)

    return UploadResult(s3_uri=s3_uri)


def serve_form(bucket: str, region: Optional[str], port: int) -> None:
    """Serve the passport records page and accept uploads from this computer."""
    auth_path = Path(__file__).with_name("Authentication.html")
    home_path = Path(__file__).with_name("Home.html")
    form_path = Path(__file__).with_name("FileCaptureForm.html")
    edit_path = Path(__file__).with_name("Edit.html")
    delete_path = Path(__file__).with_name("Delete.html")
    sessions: dict[str, float] = {}

    class UploadHandler(BaseHTTPRequestHandler):
        def _session_token(self) -> Optional[str]:
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except CookieError:
                return None
            morsel = cookie.get("session")
            return morsel.value if morsel is not None else None

        def _is_authenticated(self) -> bool:
            token = self._session_token()
            if token is None:
                return False
            expires_at = sessions.get(token)
            if expires_at is None:
                return False
            if expires_at <= time.monotonic():
                sessions.pop(token, None)
                return False
            return True

        def _require_authentication(self, api: bool = False) -> bool:
            if self._is_authenticated():
                return True
            if api:
                self._send_json(401, {"error": "Sign in to continue."})
            else:
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return False

        def _set_session(self) -> None:
            token = secrets.token_urlsafe(32)
            now = time.monotonic()
            for expired_token in [
                key for key, expires_at in sessions.items() if expires_at <= now
            ]:
                sessions.pop(expired_token, None)
            sessions[token] = now + SESSION_DURATION_SECONDS
            self.send_header(
                "Set-Cookie",
                f"session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_DURATION_SECONDS}",
            )

        def _read_json_object(self) -> Optional[dict[str, object]]:
            if self.headers.get_content_type() != "application/json":
                self._send_json(415, {"error": "Content-Type must be application/json."})
                return None
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(411, {"error": "A valid Content-Length header is required."})
                return None
            if size <= 0 or size > 16 * 1024:
                self._send_json(413, {"error": "Request must be between 1 byte and 16 KB."})
                return None
            try:
                payload = json.loads(self.rfile.read(size))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "Request body must contain valid JSON."})
                return None
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "Request body must be a JSON object."})
                return None
            return payload

        def _handle_authentication(self, signup: bool) -> None:
            payload = self._read_json_object()
            if payload is None:
                return
            username = payload.get("username")
            password = payload.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                self._send_json(400, {"error": "Username and password are required."})
                return
            try:
                if signup:
                    create_auth_user(username, password, rds_connection_options())
                elif not authenticate_user(username, password, rds_connection_options()):
                    self._send_json(401, {"error": "Incorrect username or password."})
                    return
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self._send_json(500, {"error": str(exc)})
                return
            except MySQLError:
                logging.exception("Authentication database request failed")
                self._send_json(500, {"error": "Could not access the authentication table."})
                return

            self._send_response_with_session()

        def _send_response_with_session(self) -> None:
            body = json.dumps({"message": "Signed in successfully."}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self._set_session()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                if self._is_authenticated():
                    self.send_response(303)
                    self.send_header("Location", "/Home.html")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                page_path = auth_path
            elif path == "/records":
                if not self._require_authentication(api=True):
                    return
                try:
                    columns, records, primary_keys = fetch_passport_records(rds_connection_options())
                except (MySQLError, RuntimeError, ValueError):
                    logging.exception("Could not fetch passport records from RDS")
                    self._send_json(500, {"error": "Could not load passport records from RDS."})
                    return

                self._send_json(
                    200,
                    {"columns": columns, "records": records, "primary_keys": primary_keys},
                )
                return
            else:
                page_path = {
                    "/Authentication.html": auth_path,
                    "/Home.html": home_path,
                    "/FileCaptureForm.html": form_path,
                    "/Edit.html": edit_path,
                    "/Delete.html": delete_path,
                }.get(path)
                if page_path is None:
                    self.send_error(404)
                    return
                if path != "/Authentication.html" and not self._require_authentication():
                    return

            if page_path == auth_path and self._is_authenticated():
                self.send_response(303)
                self.send_header("Location", "/Home.html")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            try:
                page = page_path.read_bytes()
            except OSError as exc:
                logging.exception("Could not read page %s", page_path.name)
                self.send_error(500, str(exc))
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if path == "/auth/signup":
                self._handle_authentication(signup=True)
                return
            if path == "/auth/signin":
                self._handle_authentication(signup=False)
                return
            if path == "/auth/signout":
                token = self._session_token()
                if token is not None:
                    sessions.pop(token, None)
                body = json.dumps({"message": "Signed out."}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not self._require_authentication(api=True):
                return
            if path == "/records/update":
                self._handle_record_update()
                return
            if path == "/records/delete":
                self._handle_record_delete()
                return
            if path != "/upload":
                self.send_error(404)
                return

            if self.headers.get_content_type() != "application/octet-stream":
                self._send_json(415, {"error": "Unsupported upload content type."})
                return

            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(411, {"error": "A valid Content-Length header is required."})
                return
            if size <= 0 or size > MAX_UPLOAD_SIZE:
                self._send_json(413, {"error": "File must be between 1 byte and 100 MB."})
                return

            query = parse_qs(urlsplit(self.path).query)
            filename = Path(query.get("filename", [""])[0]).name
            if not filename or filename in {".", ".."}:
                self._send_json(400, {"error": "A valid filename is required."})
                return

            try:
                details = validate_passport_details(
                    PassportDetails(
                        **{
                            field: unquote(
                                self.headers.get(
                                    f"X-Passport-{field.replace('_', '-')}",
                                    "",
                                )
                            )
                            for field in PassportDetails.__dataclass_fields__
                        }
                    )
                )
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return

            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir) / "upload"
                    with temp_path.open("wb") as temp_file:
                        remaining = size
                        while remaining:
                            chunk = self.rfile.read(min(remaining, 1024 * 1024))
                            if not chunk:
                                raise ValueError("The uploaded file ended unexpectedly.")
                            temp_file.write(chunk)
                            remaining -= len(chunk)
                    result = upload_file(
                        temp_path,
                        bucket,
                        object_key=filename,
                        region=region,
                        passport_details=details,
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                logging.exception("Upload failed")
                self._send_json(500, {"error": str(exc)})
                return

            self._send_json(
                200,
                {
                    "message": "Upload successful.",
                    "s3_uri": result.s3_uri,
                    "rds_warning": result.rds_warning,
                },
            )

        def _handle_record_update(self) -> None:
            if self.headers.get_content_type() != "application/json":
                self._send_json(415, {"error": "Content-Type must be application/json."})
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(411, {"error": "A valid Content-Length header is required."})
                return
            if size <= 0 or size > 1024 * 1024:
                self._send_json(413, {"error": "Update request must be between 1 byte and 1 MB."})
                return

            try:
                payload = json.loads(self.rfile.read(size))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "Request body must contain valid JSON."})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "Request body must be a JSON object."})
                return
            key = payload.get("key")
            values = payload.get("values")
            if not isinstance(key, dict) or not isinstance(values, dict):
                self._send_json(400, {"error": "Request must include record key and updated values."})
                return
            try:
                normalized_values = validate_record_updates(values)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return

            try:
                update_passport_record(key, normalized_values, rds_connection_options())
            except LookupError as exc:
                self._send_json(404, {"error": str(exc)})
                return
            except (MySQLError, RuntimeError, ValueError) as exc:
                logging.exception("Could not update passport record in RDS")
                self._send_json(500, {"error": f"Could not update passport record: {exc}"})
                return

            self._send_json(200, {"message": "Passport record updated successfully."})

        def _handle_record_delete(self) -> None:
            if self.headers.get_content_type() != "application/json":
                self._send_json(415, {"error": "Content-Type must be application/json."})
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send_json(411, {"error": "A valid Content-Length header is required."})
                return
            if size <= 0 or size > 1024 * 1024:
                self._send_json(413, {"error": "Delete request must be between 1 byte and 1 MB."})
                return

            try:
                payload = json.loads(self.rfile.read(size))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "Request body must contain valid JSON."})
                return
            if not isinstance(payload, dict) or not isinstance(payload.get("key"), dict):
                self._send_json(400, {"error": "Request must include the selected record key."})
                return

            try:
                delete_passport_record(payload["key"], rds_connection_options())
            except LookupError as exc:
                self._send_json(404, {"error": str(exc)})
                return
            except (MySQLError, RuntimeError, ValueError) as exc:
                logging.exception("Could not delete passport record from RDS")
                self._send_json(500, {"error": f"Could not delete passport record: {exc}"})
                return

            self._send_json(200, {"message": "Passport record deleted successfully."})

        def _send_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("0.0.0.0", port), UploadHandler)
    print(f"Open http://0.0.0.0:{port} to view passport records and upload to s3://{bucket}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nUpload server stopped.")
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload a local file to Amazon S3.")
    parser.add_argument("file_path", type=Path, nargs="?", help="Path to the local file")
    parser.add_argument("bucket", nargs="?", help="Name of the destination S3 bucket")
    parser.add_argument(
        "--key",
        dest="object_key",
        help="Object key in S3 (defaults to the local file's name)",
    )
    parser.add_argument("--region", help="AWS region for the bucket, if needed")
    parser.add_argument("--bucket", dest="serve_bucket", help="S3 bucket for --serve")
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Serve the browser upload form instead of uploading a local file",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for --serve (default: 8000)")
    args = parser.parse_args()

    if args.serve:
        if args.file_path is not None or args.bucket or not args.serve_bucket:
            parser.error("Use --serve with the bucket name: --serve --bucket NAME")
        if not 1 <= args.port <= 65535:
            parser.error("--port must be between 1 and 65535")
        serve_form(args.serve_bucket, args.region, args.port)
        return 0

    if args.serve_bucket or args.file_path is None or not args.bucket:
        parser.error("file_path and bucket are required unless --serve is used")

    try:
        result = upload_file(
            args.file_path,
            args.bucket,
            object_key=args.object_key,
            region=args.region,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Upload successful: {result.s3_uri}")
    if result.rds_warning:
        print(result.rds_warning)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())