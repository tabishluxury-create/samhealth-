from types import SimpleNamespace

import app
import database


def test_demo_accounts_are_seeded_with_names_passwords_and_pins(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", str(tmp_path / "healthcare.db"))
    database.init_database()

    app.create_demo_seed_data()

    for account in app.DEMO_ACCOUNTS:
        authenticate = (
            database.authenticate_patient
            if account["role"] == "patient"
            else database.authenticate_doctor
        )
        profile = authenticate(account["id"], account["password"])
        assert profile is not None
        profile = (
            database.get_patient(account["id"])
            if account["role"] == "patient"
            else database.get_doctor(account["id"])
        )
        assert profile["name"] == account["name"]
        assert database.verify_security_pin(account["role"], account["id"], account["pin"])


def test_registration_does_not_require_removed_identity_fields(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", str(tmp_path / "healthcare.db"))
    database.init_database()
    handler = app.HealthcareRequestHandler.__new__(app.HealthcareRequestHandler)
    responses = []
    handler.send_json = lambda status, payload: responses.append((status, payload))

    handler.handle_registration({
        "role": "doctor",
        "name": "Dr. Example",
        "phone": "+923001110000",
        "email": "doctor@example.com",
        "password": "StrongPass123!",
        "security_pin": "2468",
        "specialization": "Cardiology",
    })

    status, result = responses.pop()
    assert status == 201
    profile = database.get_doctor(result["account_id"])
    assert profile["name"] == "Dr. Example"


def test_demo_account_pdf_contains_every_named_account_and_credential():
    pdf = app.build_demo_accounts_pdf()

    assert pdf.startswith(b"%PDF-1.4")
    assert b"startxref" in pdf
    for account in app.DEMO_ACCOUNTS:
        for value in (account["name"], account["id"], account["password"], account["pin"]):
            assert value.encode("ascii") in pdf


def test_demo_account_pdf_is_local_only_and_disabled_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    sent = []
    handler = SimpleNamespace(
        path="/demo-accounts.pdf",
        client_address=("127.0.0.1", 12345),
        send_json=lambda status, payload: sent.append(("json", status, payload)),
        send_pdf=lambda content, filename: sent.append(("pdf", content, filename)),
    )

    app.HealthcareRequestHandler.do_GET(handler)
    assert sent[0][0] == "pdf"
    assert sent[0][2] == "demo-account-credentials.pdf"

    sent.clear()
    handler.client_address = ("192.0.2.10", 12345)
    app.HealthcareRequestHandler.do_GET(handler)
    assert sent[0][0:2] == ("json", 403)

    sent.clear()
    monkeypatch.setenv("APP_ENV", "production")
    handler.client_address = ("127.0.0.1", 12345)
    app.HealthcareRequestHandler.do_GET(handler)
    assert sent[0][0:2] == ("json", 404)
