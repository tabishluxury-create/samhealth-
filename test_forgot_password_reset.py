import sqlite3

from database import (
    init_database,
    register_patient,
    register_doctor,
    reset_account_credentials,
    get_db,
    get_patient,
    get_doctor,    patient_exists,
    doctor_exists,)


def test_get_patient_and_get_doctor_lookup():
    init_database()
    conn = sqlite3.connect('healthcare.db')
    conn.execute("DELETE FROM patient_accounts WHERE id LIKE 'TEST%'")
    conn.execute("DELETE FROM patients WHERE id LIKE 'TEST%'")
    conn.execute("DELETE FROM doctor_accounts WHERE id LIKE 'DOC%'")
    conn.execute("DELETE FROM doctors WHERE id LIKE 'DOC%'")
    conn.commit()
    conn.close()

    patient_id = 'TESTP101'
    doctor_id = 'DOC999'
    assert register_patient(patient_id, 'Lookup Patient', '+923000000101', 'lookup.patient@example.com', 'Password123', 29, 'Female', 'A+', '1234')
    assert register_doctor(doctor_id, 'Lookup Doctor', '+923000000999', 'lookup.doctor@example.com', 'doctor123', 'Cardiology', 'MD', 8, '1234', 'Consultant', 'LIC123', 'Cardiology', 'City Hospital')

    patient = get_patient(patient_id)
    doctor = get_doctor(doctor_id)

    assert patient is not None
    assert patient['id'] == patient_id
    assert doctor is not None
    assert doctor['id'] == doctor_id


def test_reset_account_credentials(monkeypatch, tmp_path):
    import database

    monkeypatch.setattr(database, 'DB_FILE', str(tmp_path / 'healthcare.db'))
    init_database()

    patient_id = 'TESTP001'
    assert register_patient(
        patient_id,
        'Test Patient',
        '+923001234567',
        'test@example.com',
        'Password123',
        30,
        'Male',
        'O+',
        '1234',
    )

    success = reset_account_credentials('patient', patient_id, 'NewPass123', '4321')
    assert success is True

    conn = sqlite3.connect(database.DB_FILE)
    row = conn.execute(
        "SELECT password_hash, security_pin_hash FROM patient_accounts WHERE id = ?",
        (patient_id,),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] != '0'
    assert row[1] != '0'


def test_whatsapp_password_reset_otp_flow(monkeypatch):
    import app as app_module

    handler = app_module.HealthcareRequestHandler.__new__(app_module.HealthcareRequestHandler)
    responses = []
    sent_messages = []
    account = {'patient_id': 'TESTPOTP', 'phone': '+923001234567'}
    handler.send_json = lambda status, payload: responses.append((status, payload))
    handler.find_account = lambda role, identifier: account

    monkeypatch.setattr(app_module, 'RESET_OTP_CHALLENGES', {})
    monkeypatch.setattr(app_module, 'RESET_TOKENS', {})
    monkeypatch.setattr(app_module, 'send_whatsapp_otp', lambda phone, code: (
        sent_messages.append((phone, code)) or {'sent': True, 'message': 'WhatsApp code sent.'}
    ))
    monkeypatch.setattr(app_module.secrets, 'randbelow', lambda upper_bound: 12345)

    handler.handle_password_reset_request({'role': 'patient', 'identifier': 'TESTPOTP'})

    status, response = responses.pop()
    assert status == 200
    assert sent_messages == [('+923001234567', '012345')]
    assert response['challenge_id']
    challenge_id = response['challenge_id']
    assert app_module.RESET_TOKENS == {}

    handler.handle_password_reset_request({'role': 'patient', 'identifier': 'TESTPOTP'})
    status, response = responses.pop()
    assert status == 429
    assert response['retry_after_seconds'] > 0
    assert len(sent_messages) == 1

    handler.handle_password_reset_verification({
        'challenge_id': challenge_id,
        'otp': '999999',
    })
    status, response = responses.pop()
    assert status == 401
    assert challenge_id in app_module.RESET_OTP_CHALLENGES

    handler.handle_password_reset_verification({
        'challenge_id': challenge_id,
        'otp': sent_messages[0][1],
    })
    status, response = responses.pop()
    assert status == 200
    assert response['reset_token'] in app_module.RESET_TOKENS
    assert app_module.RESET_TOKENS[response['reset_token']]['account']['id'] == 'TESTPOTP'
    assert challenge_id not in app_module.RESET_OTP_CHALLENGES


def test_whatsapp_password_reset_otp_locks_after_five_attempts(monkeypatch):
    import app as app_module
    import time

    handler = app_module.HealthcareRequestHandler.__new__(app_module.HealthcareRequestHandler)
    responses = []
    handler.send_json = lambda status, payload: responses.append((status, payload))
    challenge_id = 'test-challenge'
    monkeypatch.setattr(app_module, 'RESET_OTP_CHALLENGES', {
        challenge_id: {
            'role': 'patient',
            'account': {'patient_id': 'TESTPOTP'},
            'otp': '012345',
            'attempts': 0,
            'sent_at': time.time(),
            'expires_at': time.time() + 300,
        }
    })

    for _ in range(5):
        handler.handle_password_reset_verification({
            'challenge_id': challenge_id,
            'otp': '999999',
        })

    status, response = responses[-1]
    assert status == 401
    assert response['message'] == 'Too many incorrect codes. Request a new code.'
    assert challenge_id not in app_module.RESET_OTP_CHALLENGES


def test_send_whatsapp_otp_uses_approved_content_template(monkeypatch):
    import app as app_module
    from io import BytesIO
    from urllib.parse import parse_qs

    sent_requests = []

    class TwilioResponse(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setenv('TWILIO_ACCOUNT_SID', 'AC_TEST')
    monkeypatch.setenv('TWILIO_AUTH_TOKEN', 'test-token')
    monkeypatch.setenv('TWILIO_WHATSAPP_FROM', 'whatsapp:+14155238886')
    monkeypatch.setenv('TWILIO_WHATSAPP_OTP_CONTENT_SID', 'HX_TEST')
    monkeypatch.setattr(app_module, 'urlopen', lambda request, timeout: (
        sent_requests.append(request) or TwilioResponse(b'{}')
    ))

    result = app_module.send_whatsapp_otp('+923001234567', '012345')

    assert result['sent'] is True
    payload = parse_qs(sent_requests[0].data.decode('utf-8'))
    assert payload['To'] == ['whatsapp:+923001234567']
    assert payload['ContentSid'] == ['HX_TEST']
    assert payload['ContentVariables'] == ['{"1": "012345"}']


def test_mock_whatsapp_otp_appears_in_local_saman_health_inbox(monkeypatch):
    import app as app_module

    monkeypatch.setenv('WHATSAPP_OTP_MODE', 'mock')
    monkeypatch.delenv('APP_ENV', raising=False)
    monkeypatch.setattr(app_module, 'RESET_OTP_CHALLENGES', {})
    monkeypatch.setattr(app_module, 'LOCAL_WHATSAPP_INBOX_MESSAGES', [])
    monkeypatch.setattr(app_module.secrets, 'randbelow', lambda upper_bound: 12345)

    handler = app_module.HealthcareRequestHandler.__new__(app_module.HealthcareRequestHandler)
    handler.client_address = ('127.0.0.1', 12345)
    responses = []
    handler.send_json = lambda status, payload: responses.append((status, payload))
    handler.find_account = lambda role, identifier: {
        'patient_id': 'TESTPDEMO',
        'phone': '+923001234567',
    }

    handler.handle_password_reset_request({'role': 'patient', 'identifier': 'TESTPDEMO'})
    status, request_response = responses.pop()
    assert status == 200
    assert request_response['delivery_mode'] == 'local_preview'
    assert 'demo_otp' not in request_response

    handler.handle_saman_health_inbox_messages()
    status, inbox_response = responses.pop()
    assert status == 200
    assert inbox_response['mode'] == 'local_preview'
    saman_conversation = inbox_response['conversations'][0]
    assert saman_conversation['contact_name'] == 'Saman Health'
    assert '012345' in saman_conversation['messages'][0]['body']

    handler.handle_password_reset_verification({
        'challenge_id': request_response['challenge_id'],
        'otp': '012345',
    })
    status, _ = responses.pop()
    assert status == 200
    handler.handle_saman_health_inbox_messages()
    _, inbox_response = responses.pop()
    saman_conversation = inbox_response['conversations'][0]
    assert saman_conversation['messages'][0]['body'] == 'Your password reset code was verified.'


def test_saved_prescriptions_and_reports_create_patient_specific_inbox_chats(monkeypatch):
    import app as app_module

    monkeypatch.setenv('WHATSAPP_OTP_MODE', 'mock')
    monkeypatch.delenv('APP_ENV', raising=False)
    monkeypatch.setattr(app_module, 'LOCAL_WHATSAPP_INBOX_MESSAGES', [])
    monkeypatch.setattr(app_module, 'add_prescription', lambda data: True)
    monkeypatch.setattr(app_module, 'add_lab_report', lambda data: True)
    monkeypatch.setattr(app_module, 'add_notification', lambda *args: None)
    monkeypatch.setattr(app_module, 'get_patient', lambda patient_id: {
        'id': patient_id,
        'name': f'Patient {patient_id}',
        'phone': '+923001234567',
    })

    handler = app_module.HealthcareRequestHandler.__new__(app_module.HealthcareRequestHandler)
    handler.client_address = ('127.0.0.1', 12345)
    responses = []
    handler.send_json = lambda status, payload: responses.append((status, payload))

    handler.handle_prescriptions_api({
        'action': 'add',
        'patient_id': 'PATIENT-A',
        'medicine_name': 'Medication A',
        'dosage': 'One tablet',
        'frequency': 'Daily',
        'duration': '7 days',
    })
    assert responses.pop()[1]['inbox_updated'] is True

    handler.handle_lab_reports_api({
        'action': 'add',
        'patient_id': 'PATIENT-B',
        'report_type': 'Blood test',
        'report_data': 'Results normal',
    })
    assert responses.pop()[1]['inbox_updated'] is True

    handler.handle_saman_health_inbox_messages()
    status, inbox_response = responses.pop()
    assert status == 200
    conversations = {
        conversation['conversation_id']: conversation
        for conversation in inbox_response['conversations']
    }
    assert set(conversations) == {'PATIENT-A', 'PATIENT-B'}
    assert conversations['PATIENT-A']['contact_name'] == 'Patient PATIENT-A'
    assert conversations['PATIENT-A']['messages'][0]['category'] == 'prescription'
    assert 'Medication A' in conversations['PATIENT-A']['messages'][0]['body']
    assert conversations['PATIENT-B']['messages'][0]['category'] == 'lab_report'
    assert 'Results normal' in conversations['PATIENT-B']['messages'][0]['body']

    monkeypatch.setattr(app_module, 'add_prescription', lambda data: False)
    handler.handle_prescriptions_api({'action': 'add', 'patient_id': 'PATIENT-A'})
    assert responses.pop()[1]['success'] is False
    assert len(app_module.LOCAL_WHATSAPP_INBOX_MESSAGES) == 2


def test_mock_whatsapp_inbox_is_loopback_only(monkeypatch):
    import app as app_module

    monkeypatch.setenv('WHATSAPP_OTP_MODE', 'mock')
    handler = app_module.HealthcareRequestHandler.__new__(app_module.HealthcareRequestHandler)
    handler.client_address = ('192.0.2.10', 12345)
    responses = []
    handler.send_json = lambda status, payload: responses.append((status, payload))

    handler.handle_saman_health_inbox_messages()

    status, response = responses.pop()
    assert status == 403
    assert 'only on this device' in response['message']

    handler.client_address = ('127.0.0.1', 12345)
    monkeypatch.setenv('APP_ENV', 'production')
    handler.handle_saman_health_inbox_messages()
    status, response = responses.pop()
    assert status == 404
    assert response['message'] == 'The Saman Health inbox is not enabled on this server.'


def test_demo_accounts_are_seeded_with_unique_phones_and_login_credentials():
    from backend.app import create_demo_seed_data
    init_database()

    conn = sqlite3.connect('healthcare.db')
    conn.execute("DELETE FROM patient_accounts WHERE id LIKE 'P100%' OR id = 'P1001'")
    conn.execute("DELETE FROM patients WHERE id LIKE 'P100%' OR id = 'P1001'")
    conn.execute("DELETE FROM doctor_accounts WHERE id LIKE 'D200%'")
    conn.execute("DELETE FROM doctors WHERE id LIKE 'D200%'")
    conn.commit()
    conn.close()

    create_demo_seed_data()

    assert patient_exists('P1001') is True
    assert doctor_exists('D2001') is True
    assert patient_exists('P1002') is True
    assert doctor_exists('D2002') is True

    conn = sqlite3.connect('healthcare.db')
    try:
        phone_rows = conn.execute(
            "SELECT id, phone FROM patient_accounts WHERE id IN ('P1001','P1002','P1003','P1004') UNION ALL SELECT id, phone FROM doctor_accounts WHERE id IN ('D2001','D2002','D2003')"
        ).fetchall()
    finally:
        conn.close()

    phones = [row[1] for row in phone_rows]
    assert len(phones) == len(set(phones))


def test_repo_root_entrypoint_exists_and_exposes_main():
    import importlib.util
    from pathlib import Path

    root_app = Path(__file__).resolve().parent / 'app.py'
    assert root_app.exists(), 'Repository root app.py is missing.'

    spec = importlib.util.spec_from_file_location('repo_root_app', root_app)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    assert hasattr(module, 'main')


def test_input_sanitization_and_validation_helpers():
    from backend.database import (
        sanitize_text,
        validate_email,
        validate_password,
        validate_security_pin,
        normalize_phone,
    )

    assert sanitize_text("  <script>alert(1)</script>\n  ") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert normalize_phone(" +92 (300) 123-4567 ") == "+923001234567"
    assert validate_email("user.name+tag@example.co.uk") == "user.name+tag@example.co.uk"
    assert validate_email("bad@@example.com") is None
    assert validate_password("pass") is False
    assert validate_password("StrongPassword1!") is True
    assert validate_security_pin("123") is False
    assert validate_security_pin("1234") is True
