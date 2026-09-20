"""Authoritative US state codes.

The 50 states are the accepted set for ``location.state``. DC and the
territories are tracked separately because they appear in the census file and in
our state scraper configs, but a nonprofit's home location is validated against
the 50 only - matching the requirement that a state code is "valid US state
(50)".
"""

from __future__ import annotations

# The 50 states. Source: US Census Bureau state FIPS reference file, which
# lists 57 entries; these 50 exclude DC and the six territories (AS GU MP PR UM VI).
STATES_50: frozenset[str] = frozenset(
    {
        "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
        "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
        "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
        "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
        "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    }
)

# Tracked by the scraper, but not valid as a nonprofit's home state.
DISTRICT_AND_TERRITORIES: frozenset[str] = frozenset({"DC", "AS", "GU", "MP", "PR", "UM", "VI"})

# The pseudo-state used in matching_rules to mean "funding available anywhere".
NATIONAL = "national"

STATE_NAMES: dict[str, str] = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware",
    "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
    "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas",
    "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah",
    "VT": "Vermont", "VA": "Virginia", "WA": "Washington", "WV": "West Virginia",
    "WI": "Wisconsin", "WY": "Wyoming",
}


class InvalidStateCode(ValueError):
    """Raised when a location state is not one of the 50 US states."""


def is_valid_state(code: str | None) -> bool:
    return bool(code) and str(code).strip().upper() in STATES_50


def validate_state(code: str | None, *, allow_national: bool = False, field: str = "location.state") -> str:
    """Normalise and validate a state code, or raise :class:`InvalidStateCode`.

    A malformed location must fail loudly: silently defaulting would point the
    Hunter at the wrong state's funders and quietly waste a run.
    """
    normalised = (code or "").strip().upper()
    if allow_national and normalised == NATIONAL.upper():
        return NATIONAL
    if normalised not in STATES_50:
        raise InvalidStateCode(
            f"{field}={code!r} is not a valid US state code. "
            f"Expected one of the 50 (examples: CA, WI, TX)"
            + (", or 'national'." if allow_national else ".")
        )
    return normalised


def state_name(code: str) -> str:
    return STATE_NAMES.get((code or "").strip().upper(), "")


__all__ = [
    "DISTRICT_AND_TERRITORIES",
    "NATIONAL",
    "STATES_50",
    "STATE_NAMES",
    "InvalidStateCode",
    "is_valid_state",
    "state_name",
    "validate_state",
]