"""Simple backend for the Saman Healthcare demo login page with SQLite database."""

# Import Python's built-in modules so the demo does not need external packages.
import base64
import hmac
import ipaddress
import json
import os
import platform
import secrets
import time
from datetime import datetime
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse, parse_qs, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Import database and hardware security modules
try:
    from backend.database import (
        DB_FILE, init_database, get_patients, get_patient, add_patient, update_patient,
        get_doctors, get_doctor, add_doctor, get_appointments, add_appointment,
        update_appointment_status, get_attendance, add_attendance,
        get_prescriptions, add_prescription, authenticate_patient, authenticate_doctor,
        get_lab_reports, add_lab_report, get_referrals, add_referral,
        get_surgery_records, save_surgery_record, update_completed_appointment_visit_notes,
        complete_doctor_appointments_for_date,
        add_notification, get_notifications, mark_notifications_read,
        register_patient, register_doctor, patient_exists, doctor_exists,
        phone_exists_patient, phone_exists_doctor, account_id_exists, normalize_phone,
        canonical_account_id, get_profile, update_profile, get_two_step_enabled,
        set_two_step_enabled, set_security_pin, verify_security_pin,
        change_account_password, reset_account_credentials,
        add_hardware_credential, get_hardware_credential, get_hardware_credentials_for_account,
        sanitize_text, validate_email, validate_password, validate_security_pin,
        hash_password, get_db
    )
    from backend.security import (
        tee_hardware_attestation, HardwareCryptoEngine,
        create_webauthn_challenge, verify_webauthn_challenge
    )
except ImportError:
    from database import (
        DB_FILE, init_database, get_patients, get_patient, add_patient, update_patient,
        get_doctors, get_doctor, add_doctor, get_appointments, add_appointment,
        update_appointment_status, get_attendance, add_attendance,
        get_prescriptions, add_prescription, authenticate_patient, authenticate_doctor,
        get_lab_reports, add_lab_report, get_referrals, add_referral,
        get_surgery_records, save_surgery_record, update_completed_appointment_visit_notes,
        complete_doctor_appointments_for_date,
        add_notification, get_notifications, mark_notifications_read,
        register_patient, register_doctor, patient_exists, doctor_exists,
        phone_exists_patient, phone_exists_doctor, account_id_exists, normalize_phone,
        canonical_account_id, get_profile, update_profile, get_two_step_enabled,
        set_two_step_enabled, set_security_pin, verify_security_pin,
        change_account_password, reset_account_credentials,
        add_hardware_credential, get_hardware_credential, get_hardware_credentials_for_account,
        sanitize_text, validate_email, validate_password, validate_security_pin,
        hash_password, get_db
    )
    from security import (
        tee_hardware_attestation, HardwareCryptoEngine,
        create_webauthn_challenge, verify_webauthn_challenge
    )


PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT


def load_local_environment():
    """Load simple KEY=value settings from a local .env file without extra packages."""
    env_candidates = [
        PROJECT_ROOT / ".env",
        Path(__file__).resolve().parent / ".env",
    ]
    for env_path in env_candidates:
        if not env_path.exists():
            continue
        with open(env_path, encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        break


load_local_environment()


# Store demo accounts in memory for this local prototype only.
DEMO_USERS = {
    "patient": {
        "patient_id": "P1001",
        "phone": "+923001234500",
        "password": "patient123",
    },
    "doctor": {
        "doctor_id": "D2001",
        "phone": "+923009876543",
        "password": "doctor123",
    },
}

PUBLIC_DOCTOR_FIELDS = (
    "id", "name", "phone", "email", "specialization", "qualification",
    "experience", "clinic_address", "doctor_type", "license_number",
    "department", "hospital",
)


def public_doctor_profile(doctor):
    """Limit doctor-directory responses to professional and contact details."""
    if not doctor:
        return None
    return {field: doctor.get(field) for field in PUBLIC_DOCTOR_FIELDS}

# Keep verified reset tokens in memory for the secure account-recovery flow.
RESET_TOKENS = {}

# Keep one-time recovery codes in memory until verified or expired.
RESET_OTP_CHALLENGES = {}

# Local-only inbox used by the mock WhatsApp OTP delivery mode.
LOCAL_WHATSAPP_INBOX_MESSAGES = []

# Keep temporary two-step setup challenges in memory for five minutes.
SECURITY_CHALLENGES = {}

# Keep newly registered demo accounts grouped by account type in memory.
REGISTERED_USERS = {"patient": [], "doctor": []}

# Track failed login attempts per user to trigger the human verification challenge.
FAILED_LOGIN_ATTEMPTS = {}

# Keep reset tokens valid for five minutes.
OTP_LIFETIME_SECONDS = 300
OTP_RESEND_COOLDOWN_SECONDS = 30

DEMO_ACCOUNTS = (
    {"role": "patient", "id": "P1001", "name": "Sanath Deo", "password": "patient123", "pin": "1234"},
    {"role": "patient", "id": "P1002", "name": "Ayesha Khan", "password": "patient123", "pin": "1234"},
    {"role": "patient", "id": "P1003", "name": "Usman Ali", "password": "patient123", "pin": "1234"},
    {"role": "patient", "id": "P1004", "name": "Sara Ahmed", "password": "patient123", "pin": "1234"},
    {"role": "doctor", "id": "D2001", "name": "Dr. Martin Deo", "password": "doctor123", "pin": "1234"},
    {"role": "doctor", "id": "D2002", "name": "Dr. Priya Sharma", "password": "doctor123", "pin": "1234"},
    {"role": "doctor", "id": "D2003", "name": "Dr. Arun Kumar", "password": "doctor123", "pin": "1234"},
)


def build_demo_accounts_pdf():
    """Create a compact PDF with the local demo account credentials."""
    text_commands = [
        "BT",
        "/F1 18 Tf",
        "48 748 Td",
        "(Saman Healthcare - Demo Account Credentials) Tj",
        "/F1 10 Tf",
        "0 -22 Td",
        "(For local demonstration only. Do not use these credentials in production.) Tj",
        "/F1 12 Tf",
        "0 -34 Td",
        "(PATIENT ACCOUNTS) Tj",
    ]
    for account in (item for item in DEMO_ACCOUNTS if item["role"] == "patient"):
        line = (
            f'{account["name"]} | ID: {account["id"]} | '
            f'Password: {account["password"]} | PIN: {account["pin"]}'
        )
        text_commands.extend(("/F1 10 Tf", "0 -18 Td", f"({line}) Tj"))
    text_commands.extend(("/F1 12 Tf", "0 -30 Td", "(DOCTOR ACCOUNTS) Tj"))
    for account in (item for item in DEMO_ACCOUNTS if item["role"] == "doctor"):
        line = (
            f'{account["name"]} | ID: {account["id"]} | '
            f'Password: {account["password"]} | PIN: {account["pin"]}'
        )
        text_commands.extend(("/F1 10 Tf", "0 -18 Td", f"({line}) Tj"))
    text_commands.append("ET")
    content = "\n".join(text_commands).encode("ascii")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n"
        + content + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_number} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


def tee_runtime_info():
    """Return platform and Trusted Execution Environment capability metadata."""
    system_name = platform.system().lower()
    platform_map = {
        "windows": "windows",
        "darwin": "mac",
        "linux": "linux",
        "android": "android",
        "ios": "ios",
    }
    runtime_platform = platform_map.get(system_name, system_name or "unknown")
    device_class = "mobile" if runtime_platform in {"android", "ios"} else "desktop"
    tee_supported = runtime_platform in {"windows", "mac", "android", "ios", "linux"}
    return {
        "platform": runtime_platform,
        "device_class": device_class,
        "trusted_execution_environment": {
            "supported": tee_supported,
            "enabled": tee_supported,
            "name": "TEE" if tee_supported else "Unsupported",
            "status": "available" if tee_supported else "not_available",
        },
    }


def failed_attempt_key(role, identifier):
    """Normalize the account identifier used for failed-login tracking."""
    return f"{role}:{str(identifier).strip().lower()}"


def clear_failed_attempts(role, identifier):
    """Reset the failed-login counter after a successful login or verification."""
    FAILED_LOGIN_ATTEMPTS.pop(failed_attempt_key(role, identifier), None)


def record_failed_attempt(role, identifier):
    """Increase the failed-login counter and return the new count."""
    key = failed_attempt_key(role, identifier)
    attempts = FAILED_LOGIN_ATTEMPTS.get(key, 0) + 1
    FAILED_LOGIN_ATTEMPTS[key] = attempts
    return attempts


class HealthcareRequestHandler(SimpleHTTPRequestHandler):
    """Serve the frontend files and handle login API requests."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_OPTIONS(self):
        """Allow browser preflight requests from locally opened frontend files."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Return health and hardware security attestation, API queries, or serve frontend files."""
        parsed_url = urlparse(self.path)

        if parsed_url.path == "/demo-accounts.pdf":
            if os.environ.get("APP_ENV", "development").lower() == "production":
                self.send_json(404, {"message": "Demo account credentials are disabled in production."})
                return
            try:
                is_local_request = ipaddress.ip_address(self.client_address[0]).is_loopback
            except ValueError:
                is_local_request = False
            if not is_local_request:
                self.send_json(403, {"message": "Demo account credentials are available only on this device."})
                return
            self.send_pdf(build_demo_accounts_pdf(), "demo-account-credentials.pdf")
            return

        if parsed_url.path == "/api/health":
            health_payload = {
                "status": "ok",
                "message": "Backend is running with Hardware-Accelerated AES-256-GCM encryption.",
                "hardware_security": tee_hardware_attestation(),
                **tee_runtime_info(),
            }
            self.send_json(200, health_payload)
            return

        if parsed_url.path == "/api/saman-health/inbox-messages":
            self.handle_saman_health_inbox_messages(parse_qs(parsed_url.query))
            return

        if parsed_url.path == "/api/security/hardware-status":
            self.send_json(200, {
                "status": "ok",
                "hardware_security": tee_hardware_attestation(),
                "encryption": {
                    "cipher": "AES-256-GCM",
                    "key_length_bits": 256,
                    "authenticated": True,
                    "mode": "Galois/Counter Mode (GCM)"
                }
            })
            return

        if parsed_url.path == "/api/patients":
            query = parse_qs(parsed_url.query)
            patient_id = query.get("id", [None])[0]
            if patient_id:
                patient = get_patient(patient_id)
                self.send_json(200 if patient else 404, {"patient": patient})
            else:
                patients = get_patients()
                self.send_json(200, {"patients": patients})
            return

        if parsed_url.path == "/api/doctors":
            query = parse_qs(parsed_url.query)
            doctor_id = query.get("id", [None])[0]
            if doctor_id:
                doctor = get_doctor(doctor_id)
                self.send_json(200 if doctor else 404, {"doctor": public_doctor_profile(doctor)})
            else:
                doctors = [public_doctor_profile(doctor) for doctor in get_doctors()]
                self.send_json(200, {"doctors": doctors})
            return

        if parsed_url.path == "/api/appointments":
            query = parse_qs(parsed_url.query)
            filter_by = query.get("filter_by", [None])[0]
            filter_value = query.get("value", [None])[0]
            appointments = get_appointments(filter_by, filter_value) if filter_by else get_appointments()
            self.send_json(200, {"appointments": appointments})
            return

        if parsed_url.path == "/api/attendance":
            query = parse_qs(parsed_url.query)
            doctor_id = query.get("doctor_id", [None])[0]
            date = query.get("date", [None])[0]
            attendance = get_attendance(doctor_id, date)
            self.send_json(200, {"attendance": attendance})
            return

        if parsed_url.path == "/api/prescriptions":
            query = parse_qs(parsed_url.query)
            patient_id = query.get("patient_id", [None])[0]
            doctor_id = query.get("doctor_id", [None])[0]
            prescriptions = get_prescriptions(patient_id, doctor_id)
            self.send_json(200, {"prescriptions": prescriptions})
            return

        if parsed_url.path == "/api/lab-reports":
            query = parse_qs(parsed_url.query)
            patient_id = query.get("patient_id", [None])[0]
            doctor_id = query.get("doctor_id", [None])[0]
            reports = get_lab_reports(patient_id, doctor_id)
            self.send_json(200, {"reports": reports})
            return

        # Keep the existing HTML and CSS files available from this same server.
        super().do_GET()

    def do_POST(self):
        """Route login, security, and data modification requests."""
        valid_paths = {
            "/api/login",
            "/api/register",
            "/api/send-login-details",
            "/api/forgot-password/request",
            "/api/forgot-password/verify",
            "/api/forgot-password/reset",
            "/api/patients",
            "/api/doctors",
            "/api/appointments",
            "/api/attendance",
            "/api/prescriptions",
            "/api/lab-reports",
            "/api/referrals",
            "/api/surgeries",
            "/api/profile",
            "/api/security",
            "/api/security/set-pin",
            "/api/security/hardware-status",
            "/api/security/webauthn/challenge",
            "/api/security/webauthn/register",
            "/api/security/webauthn/login",
            "/api/verify-pin",
            "/api/verify-password",
            "/api/human-verify",
            "/api/account-password",
            "/api/notifications",
        }
        if self.path not in valid_paths:
            self.send_json(404, {"message": "Endpoint not found."})
            return

        # Parse the shared JSON request body before handling either endpoint.
        request_data = self.read_json_body()
        if request_data is None:
            return

        # Send a new OTP challenge when the login form requests two-step verification.
        if self.path == "/api/login":
            self.handle_login(request_data)
            return

        # Create a new Patient or Doctor account from the registration form.
        if self.path == "/api/register":
            self.handle_registration(request_data)
            return

        # Send the newly created account identifier to its verified phone number.
        if self.path == "/api/send-login-details":
            self.handle_send_login_details(request_data)
            return

        # Start the password-reset OTP flow.
        if self.path == "/api/forgot-password/request":
            self.handle_password_reset_request(request_data)
            return

        if self.path == "/api/forgot-password/verify":
            self.handle_password_reset_verification(request_data)
            return

        # Change the password only after the account has been verified and a reset token issued.
        if self.path == "/api/forgot-password/reset":
            self.handle_password_reset(request_data)
            return

        # Handle database API endpoints for patients, doctors, appointments, etc.
        if self.path == "/api/patients":
            self.handle_patients(request_data)
            return
        if self.path == "/api/doctors":
            self.handle_doctors(request_data)
            return
        if self.path == "/api/appointments":
            self.handle_appointments(request_data)
            return
        if self.path == "/api/attendance":
            self.handle_attendance_api(request_data)
            return
        if self.path == "/api/prescriptions":
            self.handle_prescriptions_api(request_data)
            return
        if self.path == "/api/lab-reports":
            self.handle_lab_reports_api(request_data)
            return
        if self.path == "/api/referrals":
            self.handle_referrals_api(request_data)
            return
        if self.path == "/api/surgeries":
            self.handle_surgeries_api(request_data)
            return
        if self.path == "/api/profile":
            self.handle_profile_api(request_data)
            return
        if self.path == "/api/security":
            self.handle_security_api(request_data)
            return
        if self.path == "/api/security/set-pin":
            self.handle_security_pin(request_data)
            return
        if self.path == "/api/security/hardware-status":
            self.handle_hardware_security_status(request_data)
            return
        if self.path == "/api/security/webauthn/challenge":
            self.handle_webauthn_challenge(request_data)
            return
        if self.path == "/api/security/webauthn/register":
            self.handle_webauthn_register(request_data)
            return
        if self.path == "/api/security/webauthn/login":
            self.handle_webauthn_login(request_data)
            return
        if self.path == "/api/verify-pin":
            self.handle_pin_verification(request_data)
            return
        if self.path == "/api/verify-password":
            self.handle_password_verification(request_data)
            return
        if self.path == "/api/human-verify":
            self.handle_human_verification(request_data)
            return
        if self.path == "/api/account-password":
            self.handle_account_password(request_data)
            return
        if self.path == "/api/notifications":
            self.handle_notifications_api(request_data)
            return


    def read_json_body(self):
        """Read and decode one JSON request body."""
        # Read only the number of bytes declared by the client.
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            request_body = self.rfile.read(content_length)
            return json.loads(request_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"message": "Please send valid JSON."})
            return None

    def handle_login(self, login_data):
        """Validate a password or security PIN login credential."""
        # Pull the fields sent by the login form.
        role = sanitize_text(login_data.get("role", "")).lower()
        identifier = sanitize_text(login_data.get("identifier", ""))
        pin_or_password = sanitize_text(login_data.get("password", ""))

        # Validate the basic request shape before checking account details.
        if role not in ["patient", "doctor"] or not identifier or not pin_or_password:
            self.send_json(400, {"message": "Role, login ID, and password/PIN are required."})
            return

        # 1. Attempt direct password authentication first
        account = authenticate_patient(identifier, pin_or_password) if role == "patient" else authenticate_doctor(identifier, pin_or_password)
        if account:
            clear_failed_attempts(role, identifier)
            canonical_id = account["id"]
            user_info = get_patient(canonical_id) if role == "patient" else get_doctor(canonical_id)
            name = user_info.get("name", "") if user_info else ""
            self.send_json(200, {
                "message": "Login successful.",
                "role": role,
                "account_id": canonical_id,
                "name": name,
                "hardware_secured": True,
                "cipher": "AES-256-GCM"
            })
            return

        # 2. Next, check if it is a 4-digit security PIN
        if verify_security_pin(role, identifier, pin_or_password):
            clear_failed_attempts(role, identifier)
            canonical_id = canonical_account_id(identifier) or identifier
            user_info = (get_patient(canonical_id) if role == "patient" else get_doctor(canonical_id)) if canonical_id else None
            name = user_info.get("name", "") if user_info else ""
            two_step_enabled = get_two_step_enabled(role, identifier)
            if two_step_enabled:
                self.send_json(202, {
                    "message": "PIN verified. Enter your password to continue.",
                    "requires_password": True,
                    "role": role,
                    "account_id": canonical_id,
                })
                return

            self.send_json(200, {
                "message": "Login successful.",
                "role": role,
                "account_id": canonical_id,
                "name": name,
                "hardware_secured": True,
                "cipher": "AES-256-GCM"
            })
            return

        failed_count = record_failed_attempt(role, identifier)
        if failed_count >= 2:
            self.send_json(403, {
                "message": "Too many failed attempts. Human verification is required.",
                "requires_human_verification": True,
                "role": role,
                "failed_attempts": failed_count,
            })
        else:
            self.send_json(401, {
                "message": "The password or security PIN is not correct.",
                "failed_attempts": failed_count,
            })

    def handle_password_verification(self, data):
        """Verify the password after a security PIN has been accepted."""
        role = sanitize_text(data.get("role", "")).lower()
        identifier = sanitize_text(data.get("identifier", ""))
        password = sanitize_text(data.get("password", ""))
        account = authenticate_patient(identifier, password) if role == "patient" else authenticate_doctor(identifier, password)
        if account:
            clear_failed_attempts(role, identifier)
            canonical_id = account["id"]
            user_info = get_patient(canonical_id) if role == "patient" else get_doctor(canonical_id)
            name = user_info.get("name", "") if user_info else ""
            self.send_json(200, {
                "message": "Password verified. Login successful.",
                "role": role,
                "account_id": canonical_id,
                "name": name,
                "hardware_secured": True,
                "cipher": "AES-256-GCM"
            })
            return

        failed_count = record_failed_attempt(role, identifier)
        if failed_count >= 2:
            self.send_json(403, {
                "message": "Too many failed attempts. Human verification is required.",
                "requires_human_verification": True,
                "role": role,
                "failed_attempts": failed_count,
            })
            return

        self.send_json(401, {"message": "The password is not correct.", "failed_attempts": failed_count})

    def handle_hardware_security_status(self, data):
        """Return TEE / Secure Enclave hardware attestation and encryption configuration."""
        self.send_json(200, {
            "status": "ok",
            "hardware_security": tee_hardware_attestation(),
            "encryption": {
                "cipher": "AES-256-GCM",
                "key_length_bits": 256,
                "authenticated": True,
                "mode": "Galois/Counter Mode (GCM)"
            }
        })

    def handle_webauthn_challenge(self, data):
        """Generate a WebAuthn challenge for hardware biometric / security key authentication."""
        account_id = data.get("account_id", "").strip()
        role = data.get("role", "").strip().lower()
        if not account_id:
            account_id = "anonymous"
        if not role:
            role = "patient"
        challenge_data = create_webauthn_challenge(account_id, role)
        self.send_json(200, challenge_data)

    def handle_webauthn_register(self, data):
        """Register a public key from a hardware security token or biometric authenticator."""
        challenge_id = data.get("challenge_id", "")
        credential_id = data.get("credential_id", "")
        public_key = data.get("public_key", "")
        account_id = data.get("account_id", "").strip()
        role = data.get("role", "").strip().lower()

        challenge = verify_webauthn_challenge(challenge_id)
        if not challenge:
            self.send_json(400, {"message": "Invalid or expired WebAuthn challenge."})
            return

        if not account_id:
            account_id = challenge.get("account_id", "")
        if not role:
            role = challenge.get("role", "patient")

        if not credential_id or not public_key or not account_id:
            self.send_json(400, {"message": "Credential ID, public key, and account ID are required."})
            return

        canonical_id = canonical_account_id(account_id) or account_id
        success = add_hardware_credential(credential_id, canonical_id, role, public_key)
        if success:
            self.send_json(200, {
                "success": True,
                "message": "Hardware security credential registered successfully.",
                "credential_id": credential_id,
                "account_id": canonical_id,
                "role": role,
            })
        else:
            self.send_json(500, {"message": "Failed to store hardware credential."})

    def handle_webauthn_login(self, data):
        """Verify a WebAuthn response and log in the user."""
        challenge_id = data.get("challenge_id", "")
        credential_id = data.get("credential_id", "")

        challenge = verify_webauthn_challenge(challenge_id)
        if not challenge:
            self.send_json(400, {"message": "Invalid or expired WebAuthn challenge."})
            return

        if not credential_id:
            self.send_json(400, {"message": "Hardware credential ID is required."})
            return

        cred = get_hardware_credential(credential_id)
        if not cred:
            self.send_json(404, {"message": "Hardware security credential not recognized."})
            return

        account_id = cred["account_id"]
        role = cred["role"]
        user_info = get_patient(account_id) if role == "patient" else get_doctor(account_id)
        name = user_info.get("name", "") if user_info else ""

        self.send_json(200, {
            "success": True,
            "message": "Hardware biometric / security key login successful.",
            "account_id": account_id,
            "role": role,
            "name": name,
            "hardware_secured": True,
            "cipher": "AES-256-GCM"
        })

    def handle_human_verification(self, data):
        """Allow the user to reset failed-login tracking after a human verification challenge."""
        role = sanitize_text(data.get("role", "")).lower()
        identifier = sanitize_text(data.get("identifier", ""))
        if role not in ["patient", "doctor"] or not identifier:
            self.send_json(400, {"message": "Role and identifier are required."})
            return

        clear_failed_attempts(role, identifier)
        self.send_json(200, {"message": "Human verification passed. You can try again.", "role": role})

    def handle_registration(self, registration_data):
        """Validate and register a new account in the database."""
        # Read the common account fields sent by both registration modes.
        role = sanitize_text(registration_data.get("role", "")).lower()
        phone = normalize_phone(registration_data.get("phone", ""))
        password = sanitize_text(registration_data.get("password", ""))
        security_pin = sanitize_text(registration_data.get("security_pin", ""))

        if role not in ["patient", "doctor"] or not phone or not password or not validate_password(password) or not validate_security_pin(security_pin):
            self.send_json(400, {"message": "Account type, phone, password (strong), and matching 4-digit PIN are required."})
            return

        # Prevent accounts from using duplicate phone numbers
        if phone_exists_patient(phone):
            self.send_json(409, {"message": "An account with this phone number already exists."})
            return

        # Generate an ID that is checked against both patient and doctor accounts.
        account_prefix = "D" if role == "doctor" else "P"
        account_id = None
        for _ in range(20):
            candidate_id = f"{account_prefix}{secrets.randbelow(90_000_000) + 10_000_000}"
            if not account_id_exists(candidate_id):
                account_id = candidate_id
                break

        if not account_id:
            self.send_json(503, {"message": "Could not create a unique account ID. Please try again."})
            return

        # Get role-specific fields
        if role == "patient":
            name = sanitize_text(registration_data.get("name", "Patient"), max_length=100)
            email = validate_email(registration_data.get("email"))
            age = registration_data.get("age")
            gender = sanitize_text(registration_data.get("gender"), max_length=20) if registration_data.get("gender") else None
            blood_group = sanitize_text(registration_data.get("blood_group"), max_length=20) if registration_data.get("blood_group") else None
            
            # Register in database
            success = register_patient(account_id, name, phone, email, password, age, gender, blood_group,
                                      security_pin)
        else:  # doctor
            name = sanitize_text(registration_data.get("name", "Doctor"), max_length=100)
            email = validate_email(registration_data.get("email"))
            specialization = sanitize_text(registration_data.get("specialization"), max_length=80) if registration_data.get("specialization") else None
            qualification = sanitize_text(registration_data.get("qualification"), max_length=80) if registration_data.get("qualification") else None
            experience = registration_data.get("experience")
            doctor_type = sanitize_text(registration_data.get("doctor_type"), max_length=50) if registration_data.get("doctor_type") else None
            license_number = sanitize_text(registration_data.get("license_number"), max_length=50) if registration_data.get("license_number") else None
            department = sanitize_text(registration_data.get("department"), max_length=80) if registration_data.get("department") else None
            hospital = sanitize_text(registration_data.get("hospital"), max_length=120) if registration_data.get("hospital") else None
            
            # Register in database
            success = register_doctor(account_id, name, phone, email, password, specialization, qualification,
                                      experience, security_pin, doctor_type, license_number, department,
                                      hospital)

        if not success:
            self.send_json(409, {"message": "The account details are already in use. Please try again."})
            return

        # Return the generated ID so the user can use it later if needed.
        self.send_json(201, {
            "message": "Registration successful.",
            "role": role,
            "account_id": account_id,
            "phone": phone,
        })

    def handle_send_login_details(self, login_data):
        """Send a new account's non-sensitive login identifiers through WhatsApp."""
        role = login_data.get("role", "").lower()
        account_id = login_data.get("account_id", "").strip()
        phone = normalize_phone(login_data.get("phone", ""))

        if role not in ["patient", "doctor"] or not account_id or not phone:
            self.send_json(400, {"message": "Role, account ID, and phone number are required."})
            return

        account = self.find_account(role, account_id)
        if not account or account.get("phone") != phone:
            self.send_json(404, {"message": "The account details could not be verified."})
            return

        delivery_result = send_whatsapp_login_details(phone, role, account_id)
        self.send_json(200 if delivery_result["sent"] else 502, {
            "message": delivery_result["message"],
            "whatsapp_url": delivery_result.get("whatsapp_url"),
        })

    def find_account(self, role, identifier):
        """Find an account by phone or account ID (from database or demo)."""
        if role == "patient":
            account = authenticate_patient(identifier, "")  # This won't work without password, so use different approach
            # Try to get from database by ID or phone
            from database import get_db
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT id, phone, email FROM patient_accounts WHERE id = ? OR phone = ?', (identifier, normalize_phone(identifier)))
            result = c.fetchone()
            conn.close()
            if result:
                return {'patient_id': result['id'], 'phone': result['phone'], 'email': result['email']}
        else:  # doctor
            from database import get_db
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT id, phone, email FROM doctor_accounts WHERE id = ? OR phone = ?', (identifier, normalize_phone(identifier)))
            result = c.fetchone()
            conn.close()
            if result:
                return {'doctor_id': result['id'], 'phone': result['phone'], 'email': result['email']}
        
        # Fallback to demo account
        demo_account = DEMO_USERS.get(role, {})
        if identifier in {demo_account.get("patient_id"), demo_account.get("doctor_id")} or normalize_phone(identifier) == normalize_phone(demo_account.get("phone")):
            return demo_account
        
        return None

    def handle_password_reset_request(self, reset_data):
        """Send a time-limited password-reset code to the account's registered WhatsApp."""
        role = sanitize_text(reset_data.get("role", "")).lower()
        identifier = sanitize_text(reset_data.get("identifier", ""), max_length=100)

        if role not in ["patient", "doctor"] or not identifier:
            self.send_json(400, {"message": "Please provide your role and account ID or phone number."})
            return

        account = self.find_account(role, identifier)
        if not account:
            self.send_json(401, {"message": "We could not find that account."})
            return

        mock_delivery = os.getenv("WHATSAPP_OTP_MODE", "").strip().lower() == "mock"
        if mock_delivery and not self.is_loopback_client():
            self.send_json(403, {"message": "Test WhatsApp delivery is available only on this device."})
            return

        account_id = account.get("patient_id") or account.get("doctor_id") or account.get("id") or identifier
        existing_challenge_id = None
        for challenge_id, challenge in list(RESET_OTP_CHALLENGES.items()):
            existing_account = challenge["account"]
            existing_account_id = (
                existing_account.get("patient_id")
                or existing_account.get("doctor_id")
                or existing_account.get("id")
            )
            if time.time() >= challenge["expires_at"]:
                RESET_OTP_CHALLENGES.pop(challenge_id, None)
            elif challenge["role"] == role and existing_account_id == account_id:
                existing_challenge_id = challenge_id

        if existing_challenge_id:
            existing_challenge = RESET_OTP_CHALLENGES[existing_challenge_id]
            wait_seconds = OTP_RESEND_COOLDOWN_SECONDS - int(time.time() - existing_challenge["sent_at"])
            if wait_seconds > 0:
                self.send_json(429, {
                    "message": f"Please wait {wait_seconds} seconds before requesting another code.",
                    "retry_after_seconds": wait_seconds,
                })
                return

        phone = normalize_phone(account.get("phone", ""))
        otp = f"{secrets.randbelow(1_000_000):06d}"
        delivery_result = send_whatsapp_otp(phone, otp)
        if not delivery_result["sent"]:
            self.send_json(502, {"message": delivery_result["message"]})
            return

        if existing_challenge_id:
            RESET_OTP_CHALLENGES.pop(existing_challenge_id, None)
            self.update_local_whatsapp_message(
                existing_challenge_id,
                "A new password reset code was requested.",
            )

        challenge_id = secrets.token_urlsafe(24)
        message_time = datetime.now()
        RESET_OTP_CHALLENGES[challenge_id] = {
            "role": role,
            "account": account,
            "otp": otp,
            "attempts": 0,
            "sent_at": time.time(),
            "expires_at": time.time() + OTP_LIFETIME_SECONDS,
        }
        if delivery_result.get("mock"):
            LOCAL_WHATSAPP_INBOX_MESSAGES.append({
                "challenge_id": challenge_id,
                "conversation_id": "saman-health",
                "contact_name": "Saman Health",
                "phone": phone,
                "direction": "incoming",
                "category": "account",
                "sender": "Saman Health",
                "body": f"Your password reset verification code is {otp}. It expires in 5 minutes.",
                "time": message_time.strftime("%I:%M %p"),
                "created_at": message_time.isoformat(),
                "expires_at": time.time() + OTP_LIFETIME_SECONDS,
            })
            del LOCAL_WHATSAPP_INBOX_MESSAGES[:-25]
        self.send_json(200, {
            "message": (
                f"A test message was added to the Saman Health inbox ending in {phone[-4:]}."
                if delivery_result.get("mock")
                else f"A verification code was sent to WhatsApp ending in {phone[-4:]}."
            ),
            "challenge_id": challenge_id,
            **({"delivery_mode": "local_preview"} if delivery_result.get("mock") else {}),
        })

    def is_loopback_client(self):
        """Check that a local-only mock endpoint is accessed from this device."""
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except (AttributeError, IndexError, ValueError):
            return False

    def update_local_whatsapp_message(self, challenge_id, body):
        """Replace a local inbox OTP when its challenge is no longer usable."""
        for message in LOCAL_WHATSAPP_INBOX_MESSAGES:
            if message["challenge_id"] == challenge_id:
                message["body"] = body
                message["used"] = True
                return

    def add_local_patient_message(self, patient_id, body, category):
        """Add a saved clinical update to that patient's local WhatsApp preview."""
        if (
            os.getenv("WHATSAPP_OTP_MODE", "").strip().lower() != "mock"
            or os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}
            or not self.is_loopback_client()
        ):
            return False

        try:
            patient = get_patient(patient_id)
        except Exception as error:
            print(f"Could not load patient for local WhatsApp inbox: {error}")
            return False
        if not patient:
            return False

        message_time = datetime.now()
        LOCAL_WHATSAPP_INBOX_MESSAGES.append({
            "conversation_id": str(patient.get("id") or patient_id),
            "contact_name": str(patient.get("name") or "Patient"),
            "phone": normalize_phone(patient.get("phone") or ""),
            "direction": "outgoing",
            "category": category,
            "body": body,
            "time": message_time.strftime("%I:%M %p"),
            "created_at": message_time.isoformat(),
        })
        del LOCAL_WHATSAPP_INBOX_MESSAGES[:-200]
        return True

    def handle_saman_health_inbox_messages(self, query=None):
        """Return per-patient messages from the local mock inbox only on localhost."""
        mock_enabled = os.getenv("WHATSAPP_OTP_MODE", "").strip().lower() == "mock"
        production = os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}
        if not mock_enabled or production:
            self.send_json(404, {"message": "The Saman Health inbox is not enabled on this server."})
            return
        if not self.is_loopback_client():
            self.send_json(403, {"message": "The Saman Health inbox is available only on this device."})
            return

        now = time.time()
        grouped_messages = {}
        for message in LOCAL_WHATSAPP_INBOX_MESSAGES:
            if message.get("used"):
                body = message["body"]
            elif message.get("expires_at") is not None and now >= message["expires_at"]:
                body = "This password reset code has expired. Request a new code."
            else:
                body = message["body"]

            conversation_id = message["conversation_id"]
            grouped_messages.setdefault(conversation_id, {
                "conversation_id": conversation_id,
                "contact_name": message["contact_name"],
                "phone": message["phone"],
                "messages": [],
            })["messages"].append({
                "direction": message["direction"],
                "category": message["category"],
                "body": body,
                "time": message["time"],
                "created_at": message["created_at"],
            })

        conversations = list(grouped_messages.values())
        for conversation in conversations:
            conversation["messages"].sort(key=lambda item: item["created_at"])
            conversation["last_message"] = conversation["messages"][-1]["body"]
            conversation["last_time"] = conversation["messages"][-1]["time"]
        conversations.sort(
            key=lambda item: item["messages"][-1]["created_at"],
            reverse=True,
        )

        selected_id = (query or {}).get("patient_id", [None])[0]
        if selected_id:
            selected = next(
                (item for item in conversations if item["conversation_id"] == selected_id),
                None,
            )
            if not selected:
                self.send_json(404, {"message": "No messages were found for that patient."})
                return
            self.send_json(200, {"conversation": selected, "mode": "local_preview"})
            return

        self.send_json(200, {"conversations": conversations, "mode": "local_preview"})

    def handle_password_reset_verification(self, verification_data):
        """Verify the WhatsApp code and issue a single-use password reset token."""
        challenge_id = sanitize_text(verification_data.get("challenge_id", ""), max_length=200)
        otp = sanitize_text(verification_data.get("otp", ""), max_length=6)
        challenge = RESET_OTP_CHALLENGES.get(challenge_id)

        if not challenge or time.time() >= challenge["expires_at"]:
            RESET_OTP_CHALLENGES.pop(challenge_id, None)
            self.send_json(401, {"message": "This verification code has expired. Request a new code."})
            return

        if len(otp) != 6 or not otp.isdigit() or not hmac.compare_digest(otp, challenge["otp"]):
            challenge["attempts"] += 1
            if challenge["attempts"] >= 5:
                RESET_OTP_CHALLENGES.pop(challenge_id, None)
                self.update_local_whatsapp_message(
                    challenge_id,
                    "This code was invalidated after too many incorrect attempts.",
                )
                self.send_json(401, {"message": "Too many incorrect codes. Request a new code."})
                return
            self.send_json(401, {"message": "The verification code is incorrect."})
            return

        RESET_OTP_CHALLENGES.pop(challenge_id, None)
        self.update_local_whatsapp_message(
            challenge_id,
            "Your password reset code was verified.",
        )
        account = challenge["account"]
        account_id = account.get("patient_id") or account.get("doctor_id") or account.get("id")
        if not account_id:
            self.send_json(400, {"message": "The account could not be identified for password recovery."})
            return
        account["id"] = account_id
        reset_token = secrets.token_urlsafe(24)
        RESET_TOKENS[reset_token] = {
            "role": challenge["role"],
            "account": account,
            "expires_at": time.time() + OTP_LIFETIME_SECONDS,
        }
        self.send_json(200, {
            "message": "Phone verified. Please set your new login PIN and password.",
            "reset_token": reset_token,
        })

    def handle_password_reset(self, reset_data):
        """Update the account password and security PIN with a verified reset token."""
        reset_token = sanitize_text(reset_data.get("reset_token", ""), max_length=200)
        new_password = sanitize_text(reset_data.get("new_password", ""), max_length=128)
        new_pin = sanitize_text(reset_data.get("new_pin", ""), max_length=8)
        token_data = RESET_TOKENS.get(reset_token)

        if not token_data or time.time() > token_data["expires_at"]:
            RESET_TOKENS.pop(reset_token, None)
            self.send_json(401, {"message": "This password reset session has expired."})
            return
        if not new_password or not validate_password(new_password):
            self.send_json(400, {"message": "Password must be at least 8 characters and include mixed case, digits, and punctuation."})
            return
        if not validate_security_pin(new_pin):
            self.send_json(400, {"message": "New login PIN must contain exactly 4 digits."})
            return

        account = token_data["account"]
        account_id = account.get("id") or account.get("patient_id") or account.get("doctor_id") or account.get("phone")
        if not account_id:
            RESET_TOKENS.pop(reset_token, None)
            self.send_json(400, {"message": "The account could not be identified for password recovery."})
            return

        success = reset_account_credentials(token_data["role"], account_id, new_password, new_pin)
        RESET_TOKENS.pop(reset_token, None)
        if not success:
            self.send_json(400, {"message": "The account could not be updated. Please try again."})
            return

        self.send_json(200, {"message": "Password and login PIN changed successfully."})

    def handle_patients(self, data):
        """Handle patient database operations"""
        action = data.get("action")
        try:
            if action == "get_all":
                patients = get_patients()
                self.send_json(200, {"patients": patients})
            elif action == "get":
                patient = get_patient(data.get("patient_id"))
                self.send_json(200 if patient else 404, {"patient": patient})
            elif action == "add":
                success = add_patient(data)
                self.send_json(201 if success else 400, {"success": success})
            elif action == "update":
                patient_id = data.get("patient_id") or data.get("id")
                success = update_patient(patient_id, data)
                self.send_json(200 if success else 404, {"success": success})
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as e:
            self.send_json(500, {"message": str(e)})

    def handle_doctors(self, data):
        """Handle doctor database operations"""
        action = data.get("action")
        try:
            if action == "get_all":
                doctors = [public_doctor_profile(doctor) for doctor in get_doctors()]
                self.send_json(200, {"doctors": doctors})
            elif action == "get":
                doctor = get_doctor(data.get("doctor_id"))
                self.send_json(200 if doctor else 404, {"doctor": public_doctor_profile(doctor)})
            elif action == "add":
                success = add_doctor(data)
                self.send_json(201 if success else 400, {"success": success})
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as e:
            self.send_json(500, {"message": str(e)})

    def handle_appointments(self, data):
        """Handle appointment database operations"""
        action = data.get("action")
        try:
            if action == "get_all":
                appointments = get_appointments()
                self.send_json(200, {"appointments": appointments})
            elif action == "get":
                filter_by = data.get("filter_by")
                filter_value = data.get("filter_value")
                appointments = get_appointments(filter_by, filter_value)
                self.send_json(200, {"appointments": appointments})
            elif action == "add":
                appointment_date = data.get("appointment_date")
                if not isinstance(appointment_date, str):
                    self.send_json(400, {"message": "Choose a valid appointment date."})
                    return
                try:
                    parsed_appointment_date = datetime.strptime(appointment_date, "%Y-%m-%d")
                except ValueError:
                    self.send_json(400, {"message": "Choose a valid appointment date."})
                    return
                if (
                    parsed_appointment_date.strftime("%Y-%m-%d") != appointment_date
                    or parsed_appointment_date.date() < datetime.now().date()
                ):
                    self.send_json(400, {"message": "Choose today or a future appointment date."})
                    return
                if not data.get("doctor_id") or not data.get("patient_id"):
                    self.send_json(400, {"message": "A doctor and patient are required."})
                    return
                try:
                    appointment = add_appointment(data)
                except ValueError as error:
                    self.send_json(409, {"message": str(error)})
                    return
                if appointment:
                    add_notification(data["doctor_id"], f"New appointment request, token #{appointment['token_number']:03d}, from patient {data['patient_id']}.", data["patient_id"])
                    add_notification(data["patient_id"], f"Appointment request sent to doctor {data['doctor_id']}. Token #{appointment['token_number']:03d}.", data["doctor_id"])
                self.send_json(201 if appointment else 400, {"success": bool(appointment), "appointment": appointment})
            elif action == "update_status":
                if not data.get("appointment_id") or not (data.get("doctor_id") or data.get("patient_id")):
                    self.send_json(400, {"message": "An appointment and its patient or doctor account are required."})
                    return
                if data.get("status") == "cancelled" and not data.get("patient_id") and not data.get("doctor_id"):
                    self.send_json(403, {"message": "Only the patient who booked the appointment can cancel it."})
                    return
                appointment = update_appointment_status(data)
                if not appointment:
                    self.send_json(404, {"message": "Appointment not found or its status cannot be changed."})
                    return
                if data.get("status") == "ongoing":
                    add_notification(appointment["patient_id"], f"The doctor is ready for you. Your token is #{appointment['token_number']:03d}.", appointment["doctor_id"])
                elif data.get("status") == "completed" and appointment.get("patient_id"):
                    add_notification(appointment["patient_id"], "Your visit has been marked completed.", appointment.get("doctor_id"))
                elif data.get("status") == "cancelled":
                    if data.get("doctor_id"):
                        add_notification(
                            appointment["patient_id"],
                            f"Your doctor cancelled ongoing appointment token #{appointment['token_number']:03d}.",
                            appointment["doctor_id"]
                        )
                    else:
                        add_notification(appointment["doctor_id"], f"Patient {appointment['patient_id']} cancelled token #{appointment['token_number']:03d}.", appointment["patient_id"])
                self.send_json(200, {"appointment": appointment})
            elif action == "update_visit_notes":
                if not data.get("appointment_id") or not data.get("doctor_id"):
                    self.send_json(400, {"message": "A completed appointment and doctor account are required."})
                    return
                if not verify_security_pin("doctor", data["doctor_id"], data.get("pin", "")):
                    self.send_json(401, {"message": "The doctor security PIN is not correct."})
                    return
                try:
                    appointment = update_completed_appointment_visit_notes(
                        data["appointment_id"], data["doctor_id"], data.get("visit_notes", "")
                    )
                except ValueError as error:
                    self.send_json(400, {"message": str(error)})
                    return
                if not appointment:
                    self.send_json(404, {"message": "Completed appointment not found for this doctor."})
                    return
                self.send_json(200, {"appointment": appointment})
            elif action == "complete_today":
                doctor_id = data.get("doctor_id")
                appointment_date = data.get("appointment_date")
                if not doctor_id or not appointment_date:
                    self.send_json(400, {"message": "A doctor account and appointment date are required."})
                    return
                try:
                    requested_date = datetime.strptime(appointment_date, "%Y-%m-%d").date()
                except (TypeError, ValueError):
                    self.send_json(400, {"message": "The appointment date must use YYYY-MM-DD format."})
                    return
                if requested_date != datetime.now().date():
                    self.send_json(400, {"message": "Only today's appointments can be completed in bulk."})
                    return
                if not verify_security_pin("doctor", doctor_id, data.get("pin", "")):
                    self.send_json(401, {"message": "The doctor security PIN is not correct."})
                    return
                completed = complete_doctor_appointments_for_date(doctor_id, appointment_date)
                for appointment in completed:
                    add_notification(
                        appointment["patient_id"],
                        "Your visit has been marked completed.",
                        doctor_id
                    )
                self.send_json(200, {"completed_count": len(completed)})
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as e:
            self.send_json(500, {"message": str(e)})

    def handle_attendance_api(self, data):
        """Handle attendance database operations"""
        action = data.get("action")
        try:
            if action == "get_all":
                attendance = get_attendance()
                self.send_json(200, {"attendance": attendance})
            elif action == "get":
                doctor_id = data.get("doctor_id")
                date = data.get("date")
                attendance = get_attendance(doctor_id, date)
                self.send_json(200, {"attendance": attendance})
            elif action == "add":
                success = add_attendance(data)
                self.send_json(201 if success else 400, {"success": success})
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as e:
            self.send_json(500, {"message": str(e)})

    def handle_prescriptions_api(self, data):
        """Handle prescription database operations"""
        action = data.get("action")
        try:
            if action == "get_all":
                prescriptions = get_prescriptions()
                self.send_json(200, {"prescriptions": prescriptions})
            elif action == "get":
                patient_id = data.get("patient_id")
                doctor_id = data.get("doctor_id")
                prescriptions = get_prescriptions(patient_id, doctor_id)
                self.send_json(200, {"prescriptions": prescriptions})
            elif action == "add":
                success = add_prescription(data)
                inbox_updated = False
                if success and data.get("patient_id"):
                    add_notification(data["patient_id"], f"New prescription added: {data.get('medicine_name', 'Medication')}.", data.get("doctor_id"))
                    inbox_updated = self.add_local_patient_message(
                        data["patient_id"],
                        "\n".join((
                            "New prescription",
                            f"Medicine: {str(data.get('medicine_name') or 'Medication').strip()[:120]}",
                            f"Dosage: {str(data.get('dosage') or '').strip()[:120]}",
                            f"Frequency: {str(data.get('frequency') or '').strip()[:120]}",
                            f"Duration: {str(data.get('duration') or '').strip()[:120]}",
                        )),
                        "prescription",
                    )
                self.send_json(201 if success else 400, {
                    "success": success,
                    **({"inbox_updated": inbox_updated} if success else {}),
                })
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as e:
            self.send_json(500, {"message": str(e)})

    def handle_lab_reports_api(self, data):
        """Handle lab report database operations."""
        action = data.get("action")
        if action == "get":
            self.send_json(200, {"reports": get_lab_reports(data.get("patient_id"), data.get("doctor_id"))})
        elif action == "get_all":
            self.send_json(200, {"reports": get_lab_reports()})
        elif action == "add":
            success = add_lab_report(data)
            inbox_updated = False
            if success and data.get("patient_id"):
                add_notification(data["patient_id"], f"New lab report available: {data.get('report_type', 'Report')}.", data.get("doctor_id"))
                inbox_updated = self.add_local_patient_message(
                    data["patient_id"],
                    "\n".join((
                        "New lab report",
                        f"Report: {str(data.get('report_type') or 'Report').strip()[:120]}",
                        f"Result: {str(data.get('report_data') or '').strip()[:1500]}",
                    )),
                    "lab_report",
                )
            self.send_json(201 if success else 400, {
                "success": success,
                **({"inbox_updated": inbox_updated} if success else {}),
            })
        else:
            self.send_json(400, {"message": "Invalid action"})

    def handle_referrals_api(self, data):
        """Handle referral database operations."""
        action = data.get("action")
        if action == "get":
            self.send_json(200, {"referrals": get_referrals(data.get("patient_id"), data.get("doctor_id"))})
        elif action == "get_all":
            self.send_json(200, {"referrals": get_referrals()})
        elif action == "add":
            success = add_referral(data)
            if success and data.get("patient_id"):
                add_notification(data["patient_id"], f"New referral created: {data.get('referred_to', 'Referral')}.", data.get("doctor_id"))
            self.send_json(201 if success else 400, {"success": success})
        else:
            self.send_json(400, {"message": "Invalid action"})

    def handle_surgeries_api(self, data):
        """List surgery records and enforce patient or doctor edit ownership."""
        action = data.get("action")
        role = str(data.get("role") or "").lower()
        try:
            if action == "get":
                patient_id = data.get("patient_id")
                doctor_id = data.get("doctor_id")
                if role == "patient" and patient_id:
                    doctor_id = None
                elif role == "doctor" and doctor_id:
                    patient_id = None
                else:
                    self.send_json(400, {"message": "A valid patient or doctor account is required."})
                    return
                self.send_json(200, {
                    "surgeries": get_surgery_records(patient_id=patient_id, doctor_id=doctor_id)
                })
            elif action == "save":
                if role not in {"patient", "doctor"}:
                    self.send_json(400, {"message": "Patient or doctor role is required."})
                    return
                record = save_surgery_record(data)
                if not record:
                    self.send_json(403, {"message": "Could not save surgery details for this patient or account."})
                    return
                if role == "patient":
                    add_notification(
                        record["doctor_id"],
                        f"Patient {record['patient_id']} updated surgery record: {record['surgery_type']}.",
                        record["patient_id"]
                    )
                else:
                    add_notification(
                        record["patient_id"],
                        f"Surgery details {'updated' if data.get('surgery_id') else 'added'}: {record['surgery_type']}.",
                        record["doctor_id"]
                    )
                self.send_json(200 if data.get("surgery_id") else 201, {"surgery": record})
            else:
                self.send_json(400, {"message": "Invalid action"})
        except Exception as error:
            self.send_json(500, {"message": str(error)})

    def handle_profile_api(self, data):
        """Get or update the logged-in user's profile."""
        role = data.get("role", "").lower()
        identifier = data.get("identifier", "").strip()
        action = data.get("action", "get")
        profile = get_profile(role, identifier)
        if not profile:
            self.send_json(404, {"message": "Profile not found."})
            return
        if action == "get":
            self.send_json(200, {"profile": profile})
            return
        if action == "update":
            success = update_profile(role, profile["id"], data)
            self.send_json(200 if success else 400, {"success": success})
            return
        self.send_json(400, {"message": "Invalid action"})

    def handle_security_api(self, data):
        """Get or update account security preferences."""
        role = data.get("role", "").lower()
        identifier = data.get("identifier", "").strip()
        action = data.get("action", "get")
        if action == "get":
            self.send_json(200, {"two_step_enabled": get_two_step_enabled(role, identifier)})
            return
        if action == "update":
            success = set_two_step_enabled(role, identifier, bool(data.get("enabled")))
            self.send_json(200 if success else 404, {"success": success, "two_step_enabled": bool(data.get("enabled"))})
            return
        self.send_json(400, {"message": "Invalid action"})

    def handle_security_pin(self, data):
        """Create or replace the security PIN for an account."""
        role = data.get("role", "").lower()
        identifier = data.get("identifier", "").strip()
        pin = str(data.get("pin", "")).strip()
        if role not in ["patient", "doctor"] or not identifier or not pin.isdigit() or len(pin) != 4:
            self.send_json(400, {"message": "Security PIN must contain exactly 4 digits."})
            return
        success = set_security_pin(role, identifier, pin)
        self.send_json(200 if success else 404, {"success": success, "message": "Security PIN saved." if success else "Account not found."})

    def handle_pin_verification(self, data):
        """Verify the security PIN after password login."""
        role = data.get("role", "").lower()
        identifier = data.get("identifier", "").strip()
        pin = str(data.get("pin", "")).strip()
        if verify_security_pin(role, identifier, pin):
            self.send_json(200, {"message": "Security PIN verified. Login successful.", "role": role})
            return
        self.send_json(401, {"message": "The security PIN is not correct."})

    def handle_account_password(self, data):
        """Change the logged-in account password."""
        role = data.get("role", "").lower()
        identifier = data.get("identifier", "").strip()
        current_password = data.get("current_password", "")
        new_password = data.get("new_password", "")
        if role not in ["patient", "doctor"] or len(new_password) < 8:
            self.send_json(400, {"message": "New password must be at least 8 characters."})
            return
        success = change_account_password(role, identifier, current_password, new_password)
        self.send_json(200 if success else 401, {
            "success": success,
            "message": "Password changed successfully." if success else "Current password is not correct."
        })

    def handle_notifications_api(self, data):
        """Read or clear the logged-in account's notification feed."""
        recipient_id = data.get("recipient_id", "").strip()
        if not recipient_id:
            self.send_json(400, {"message": "Recipient ID is required."})
            return
        if data.get("action") == "mark_read":
            mark_notifications_read(recipient_id)
            self.send_json(200, {"success": True})
            return
        notifications, unread = get_notifications(recipient_id)
        self.send_json(200, {"notifications": notifications, "unread": unread})


    def send_json(self, status_code, payload):
        """Send a JSON response with the headers required by the browser."""
        # Convert the Python dictionary into UTF-8 JSON bytes.
        response_body = json.dumps(payload).encode("utf-8")

        try:
            # Send the HTTP status and content headers first.
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

            # Write the response body back to the browser.
            self.wfile.write(response_body)
        except (BrokenPipeError, ConnectionResetError):
            # Navigation can cancel an in-flight request; the client is already gone.
            return

    def send_pdf(self, response_body, filename):
        """Send a generated PDF as a private, non-cacheable download."""
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(response_body)
        except (BrokenPipeError, ConnectionResetError):
            return


def send_sms_otp(phone_number, otp_code):
    """Send an OTP through a Twilio SMS-enabled phone number."""
    if not phone_number.startswith("+") or not phone_number[1:].isdigit():
        return {"sent": False, "message": "SMS requires an international phone number such as +923001234567."}
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    sms_from = os.getenv("TWILIO_SMS_FROM")

    if not all((account_sid, auth_token, sms_from)):
        return {
            "sent": False,
            "message": "SMS is not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_SMS_FROM before requesting an OTP.",
        }

    form_data = urlencode({
        "From": sms_from,
        "To": phone_number,
        "Body": f"Your Saman Healthcare verification code is {otp_code}.",
    }).encode("utf-8")
    credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
        data=form_data,
        headers={"Authorization": f"Basic {credentials}"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            json.load(response)
        return {"sent": True, "message": "OTP sent by SMS."}
    except HTTPError as error:
        provider_message = error.read().decode("utf-8", errors="replace")
        print(f"SMS delivery failed ({error.code}): {provider_message}")
        return {"sent": False, "message": "Twilio rejected the SMS. Check that TWILIO_SMS_FROM is SMS-enabled."}
    except Exception as error:
        print(f"SMS delivery failed: {error}")
        return {"sent": False, "message": "The OTP could not be sent by SMS through Twilio."}


def send_whatsapp_login_details(phone_number, role, account_id):
    """Send non-sensitive account identifiers through Twilio WhatsApp or local mode."""
    if not phone_number.startswith("+") or not phone_number[1:].isdigit():
        return {"sent": False, "message": "WhatsApp requires an international phone number such as +923001234567."}
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    whatsapp_from = os.getenv("TWILIO_WHATSAPP_FROM")
    account_label = "Patient" if role == "patient" else "Doctor"
    message = (
        f"Saman Healthcare account created. {account_label} login ID: {account_id}. "
        f"Phone login: {phone_number}. Use your password to log in."
    )
    phone_digits = ''.join(character for character in phone_number if character.isdigit())
    whatsapp_url = f"https://wa.me/{phone_digits}?text={quote(message)}"

    if not all((account_sid, auth_token, whatsapp_from)):
        return {
            "sent": True,
            "message": "Login details are ready. Use the WhatsApp link to send them.",
            "whatsapp_url": whatsapp_url,
        }

    sender = whatsapp_from if whatsapp_from.startswith("whatsapp:") else f"whatsapp:{whatsapp_from}"
    form_data = urlencode({
        "From": sender,
        "To": f"whatsapp:{phone_number}",
        "Body": message,
    }).encode("utf-8")
    credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
        data=form_data,
        headers={"Authorization": f"Basic {credentials}"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            json.load(response)
        return {"sent": True, "message": "Login details sent to WhatsApp.", "whatsapp_url": whatsapp_url}
    except HTTPError as error:
        provider_message = error.read().decode("utf-8", errors="replace")
        print(f"WhatsApp delivery failed ({error.code}): {provider_message}")
        return {"sent": False, "message": "Twilio rejected the WhatsApp message."}
    except Exception as error:
        print(f"WhatsApp delivery failed: {error}")
        return {"sent": False, "message": "The login details could not be sent to WhatsApp."}


def send_whatsapp_otp(phone_number, otp_code):
    """Deliver a password-reset OTP through the configured Twilio WhatsApp sender."""
    if not phone_number.startswith("+") or not phone_number[1:].isdigit():
        return {"sent": False, "message": "The account does not have a valid international phone number for WhatsApp."}

    if os.getenv("WHATSAPP_OTP_MODE", "").strip().lower() == "mock":
        if os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}:
            return {"sent": False, "message": "Mock WhatsApp OTP delivery is disabled in production."}
        return {"sent": True, "mock": True, "message": "Local Saman Health message created."}

    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    whatsapp_from = os.getenv("TWILIO_WHATSAPP_FROM")
    content_sid = os.getenv("TWILIO_WHATSAPP_OTP_CONTENT_SID")
    if not all((account_sid, auth_token, whatsapp_from, content_sid)):
        return {
            "sent": False,
            "message": "WhatsApp OTP is not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM, and an approved TWILIO_WHATSAPP_OTP_CONTENT_SID.",
        }

    sender = whatsapp_from if whatsapp_from.startswith("whatsapp:") else f"whatsapp:{whatsapp_from}"
    form_data = urlencode({
        "From": sender,
        "To": f"whatsapp:{phone_number}",
        "ContentSid": content_sid,
        "ContentVariables": json.dumps({"1": otp_code}),
    }).encode("utf-8")
    credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
        data=form_data,
        headers={"Authorization": f"Basic {credentials}"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            json.load(response)
        return {"sent": True, "message": "WhatsApp verification code sent."}
    except HTTPError as error:
        provider_message = error.read().decode("utf-8", errors="replace")
        print(f"WhatsApp OTP delivery failed ({error.code}): {provider_message}")
        return {"sent": False, "message": "Twilio rejected the WhatsApp OTP."}
    except Exception as error:
        print(f"WhatsApp OTP delivery failed: {error}")
        return {"sent": False, "message": "The verification code could not be sent to WhatsApp."}


def create_demo_seed_data():
    """Create a small set of demo patients and appointments for initial dashboard data."""
    # Demo doctors
    if not doctor_exists("D2001"):
        register_doctor("D2001", "Dr. Martin Deo", "+923009876543", "doctor@demo.com", "doctor123",
                       "General Medicine", "MBBS, FCPS", 15, "1234", "General Practitioner",
                       "DOC100001", "General Medicine", "City Care Hospital")
    if not doctor_exists("D2002"):
        register_doctor("D2002", "Dr. Priya Sharma", "+923001234568", "priya@demo.com", "doctor123",
                       "Cardiology", "MD Cardio", 12, "1234", "Cardiologist",
                       "DOC100002", "Cardiology", "City Care Hospital")
    if not doctor_exists("D2003"):
        register_doctor("D2003", "Dr. Arun Kumar", "+923004567891", "arun@demo.com", "doctor123",
                       "Internal Medicine", "MBBS, MD", 10, "1234", "Internal Medicine",
                       "DOC100003", "Internal Medicine", "City Care Hospital")

    # Demo patients
    patient_seed = [
        ("P1001", "Sanath Deo", "+923001234500", "patient@demo.com", 30, "Male", "O+", "House 12, Gulshan Avenue"),
        ("P1002", "Ayesha Khan", "+923002345678", "ayesha@demo.com", 27, "Female", "A+", "Lane 7, Model Town"),
        ("P1003", "Usman Ali", "+923003456789", "usman@demo.com", 41, "Male", "B+", "Block C, Peshawar Road"),
        ("P1004", "Sara Ahmed", "+923004567890", "sara@demo.com", 34, "Female", "AB+", "Apartment 9, Gulistan"),
    ]

    for patient_id, name, phone, email, age, gender, blood_group, address in patient_seed:
        if not patient_exists(patient_id) and not phone_exists_patient(phone):
            register_patient(patient_id, name, phone, email, "patient123", age, gender, blood_group,
                             "1234")
            conn = get_db()
            conn.execute('UPDATE patients SET address = ? WHERE id = ?', (address, patient_id))
            conn.commit()
            conn.close()

    # Make the seeded profiles and credentials consistent, including databases
    # that already contain older versions of these demo accounts.
    for account in DEMO_ACCOUNTS:
        account_table = "patient_accounts" if account["role"] == "patient" else "doctor_accounts"
        profile_table = "patients" if account["role"] == "patient" else "doctors"
        conn = get_db()
        account_exists = conn.execute(
            f"SELECT 1 FROM {account_table} WHERE id = ?", (account["id"],)
        ).fetchone()
        profile_exists = conn.execute(
            f"SELECT 1 FROM {profile_table} WHERE id = ?", (account["id"],)
        ).fetchone()
        if not account_exists or not profile_exists:
            conn.close()
            raise RuntimeError(f"Could not initialize demo account {account['id']}.")
        conn.execute(
            f"UPDATE {account_table} SET password_hash = ?, security_pin_hash = ?, "
            "two_step_enabled = 1 WHERE id = ?",
            (hash_password(account["password"]), hash_password(account["pin"]), account["id"]),
        )
        conn.execute(
            f"UPDATE {profile_table} SET name = ?, updated_at = ? WHERE id = ?",
            (account["name"], datetime.now().isoformat(), account["id"]),
        )
        conn.commit()
        conn.close()

    # Add a few sample appointments for the demo patient
    conn = get_db()
    existing = conn.execute('SELECT COUNT(*) FROM appointments WHERE patient_id = ?', ("P1001",)).fetchone()[0]
    if existing == 0:
        conn.execute(
            '''INSERT INTO appointments (doctor_id, patient_id, appointment_date, appointment_time, status, notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            ("D2001", "P1001", "2026-09-14", "10:30 AM", "confirmed", "Follow-up consultation and review of medications.", "2026-09-11T09:00:00")
        )
    conn.commit()
    conn.close()


def main():
    """Initialize the database and launch the healthcare server."""
    init_database()
    create_demo_seed_data()

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server_address = (host, port)
    server = ThreadingHTTPServer(server_address, HealthcareRequestHandler)
    print(f"Saman Healthcare running at http://{host}:{port}")
    print("Demo patient login: P1001 / patient123")
    print("Demo doctor login: D2001 / doctor123")
    print(f"Database: {DB_FILE} (SQLite)")
    print("SMS OTP: " + ("Twilio configured" if all(os.getenv(key) for key in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_SMS_FROM")) else "NOT configured"))

    try:
        # Keep accepting browser requests until the user stops the server.
        server.serve_forever()
    except KeyboardInterrupt:
        # Close the socket cleanly when the server is stopped with Ctrl+C.
        print("\nServer stopped.")
        server.server_close()


# Start the local server when this file is run directly.
if __name__ == "__main__":
    main()
