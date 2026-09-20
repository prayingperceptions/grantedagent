"""Outbound email.

When SMTP is unconfigured the message is logged instead of sent. That is a
deliberate choice: local development and tests must never send real mail to
real addresses, and a deployment missing SMTP should degrade to a visible log
line rather than a 500 on the signup path.

Templates are plain text on purpose. Multipart HTML mail is a phishing surface
and buys nothing for a link that only needs to be clicked.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Final

from hunter.config import get_settings

logger = logging.getLogger("accounts.email")

SUBJECT_VERIFY: Final = "Confirm your Granted Agent email"
SUBJECT_RESET: Final = "Reset your Granted Agent password"
SUBJECT_INVITE: Final = "You have been invited to a Granted Agent organization"


class EmailError(Exception):
    """Raised when a message could not be handed to the SMTP server."""


def _body_verify(full_name: str | None, link: str) -> str:
    greeting = f"Hi {full_name}," if full_name else "Hi,"
    return (
        f"{greeting}\n\n"
        "Confirm this email address to finish setting up your Granted Agent "
        "account. The link below expires in 24 hours.\n\n"
        f"{link}\n\n"
        "If you did not create an account, you can ignore this message and no "
        "account will be activated.\n\n"
        "-- Granted Agent\n"
    )


def _body_reset(full_name: str | None, link: str) -> str:
    greeting = f"Hi {full_name}," if full_name else "Hi,"
    return (
        f"{greeting}\n\n"
        "A password reset was requested for your Granted Agent account. The "
        "link below expires in 2 hours and can be used once.\n\n"
        f"{link}\n\n"
        "If you did not request this, no action is needed - your password has "
        "not changed. Resetting it will sign out every other device.\n\n"
        "-- Granted Agent\n"
    )


def _body_invite(
    inviter: str | None, nonprofit_name: str, role: str, link: str, new_account: bool
) -> str:
    who = inviter or "An administrator"
    if new_account:
        return (
            f"{who} invited you to join {nonprofit_name} on Granted Agent as "
            f"{role}.\n\n"
            "Create your account to accept:\n\n"
            f"{link}\n\n"
            "This invitation expires in 7 days.\n\n"
            "-- Granted Agent\n"
        )
    return (
        f"{who} added you to {nonprofit_name} on Granted Agent as {role}.\n\n"
        f"Sign in to see it:\n\n{link}\n\n"
        "-- Granted Agent\n"
    )


def _mask(address: str) -> str:
    """A log-safe form of an address.

    An email address in a log file is personal data that outlives the request,
    so only enough to correlate a delivery problem is kept.
    """
    if "@" not in address:
        return "<invalid>"
    local, _, domain = address.partition("@")
    return f"<{local[:2]}***@{domain}>"


def send_email(to: str, subject: str, body: str) -> bool:
    """Send a plain-text message. Returns True when handed to the server.

    Falls back to logging when SMTP is unconfigured.
    """
    settings = get_settings()

    if not settings.email_configured:
        logger.info(
            "email suppressed (SMTP unconfigured) to=%s subject=%r body_len=%d",
            _mask(to),
            subject,
            len(body),
        )
        return False

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    try:
        if settings.smtp_use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error(
            "email send failed to_domain=%s err=%s",
            to.split("@")[-1],
            type(exc).__name__,
        )
        raise EmailError("Could not send email right now.") from exc

    return True


def send_verification(to: str, *, full_name: str | None, token: str, base_url: str) -> bool:
    link = f"{base_url.rstrip('/')}/verify-email?token={token}"
    return send_email(to, SUBJECT_VERIFY, _body_verify(full_name, link))


def send_password_reset(to: str, *, full_name: str | None, token: str, base_url: str) -> bool:
    link = f"{base_url.rstrip('/')}/reset-password?token={token}"
    return send_email(to, SUBJECT_RESET, _body_reset(full_name, link))


def send_invite(
    to: str,
    *,
    inviter: str | None,
    nonprofit_name: str,
    role: str,
    token: str,
    base_url: str,
    new_account: bool,
) -> bool:
    link = f"{base_url.rstrip('/')}/accept-invite?token={token}"
    return send_email(
        to,
        SUBJECT_INVITE,
        _body_invite(inviter, nonprofit_name, role, link, new_account),
    )


__all__ = [
    "EmailError",
    "send_email",
    "send_invite",
    "send_password_reset",
    "send_verification",
]