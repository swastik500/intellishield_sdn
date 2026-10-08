"""
R6.1 Evidence / detector registry.

Two concerns in one package boundary (no fusion):

1. Detector catalog — descriptors + adapters (roles, reliability, R2 slot)
2. Bounded evidence store — register / replace / filter / expire live results

R6.2 CollaborativeFusionEngine will consume catalog + fresh store entries.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from shared_contracts.enums import DetectorType
from shared_contracts.models import CorrelationResult, DetectorResult, new_id
from shared_contracts.timeutil import ensure_utc, utc_now
from fusion.evidence import EvidenceRecord, entity_key_from
from fusion.roles import ROLE_RATIONALE, EvidenceRole, normalize_role


@dataclass(frozen=True)
class DetectorDescriptor:
    """Static metadata for one detector/evidence source."""

    detector_type: DetectorType
    role: EvidenceRole
    name: str
    reliability: float  # default trust ∈ (0, 1] for R6.2 weighting
    notes: str = ""
    implemented: bool = True  # False → future / stub (e.g. SSL pre-R2)


AdapterFn = Callable[..., DetectorResult]

# Defaults sized for lab cycles (poll ~5s); not production-tuned magic for fusion.
DEFAULT_MAX_RECORDS = 512
DEFAULT_FRESHNESS_SECONDS = 30.0


@dataclass
class EvidenceRegistry:
    """
    Catalog of detector descriptors + bounded live evidence store.

    R6.1: register adapters + store DetectorResult / CorrelationResult.
    R6.2+: CollaborativeFusionEngine reads fresh primary/supporting/context.
    """

    max_records: int = DEFAULT_MAX_RECORDS
    default_freshness_seconds: float = DEFAULT_FRESHNESS_SECONDS
    _descriptors: Dict[str, DetectorDescriptor] = field(default_factory=dict)
    _adapters: Dict[str, AdapterFn] = field(default_factory=dict)
    # key = f"{entity_key}::{detector.value}" → EvidenceRecord (insertion order)
    _store: "OrderedDict[str, EvidenceRecord]" = field(default_factory=OrderedDict)

    # ── catalog ──────────────────────────────────────────────────────────

    def register(
        self,
        descriptor: DetectorDescriptor,
        adapter: Optional[AdapterFn] = None,
    ) -> None:
        key = descriptor.detector_type.value
        if not (0.0 < float(descriptor.reliability) <= 1.0):
            raise ValueError("reliability must be in (0, 1]")
        if int(self.max_records) < 1:
            raise ValueError("max_records must be >= 1")
        desc = DetectorDescriptor(
            detector_type=descriptor.detector_type,
            role=normalize_role(descriptor.role) or descriptor.role,
            name=descriptor.name,
            reliability=float(descriptor.reliability),
            notes=descriptor.notes,
            implemented=descriptor.implemented,
        )
        self._descriptors[key] = desc
        if adapter is not None:
            self._adapters[key] = adapter

    def get(self, detector_type: DetectorType) -> Optional[DetectorDescriptor]:
        return self._descriptors.get(detector_type.value)

    def role_of(self, detector_type: DetectorType) -> Optional[EvidenceRole]:
        d = self.get(detector_type)
        return d.role if d else None

    def list_descriptors(
        self,
        *,
        role: Optional[EvidenceRole] = None,
        implemented_only: bool = False,
    ) -> List[DetectorDescriptor]:
        want = normalize_role(role) if role is not None else None
        out = []
        for d in self._descriptors.values():
            if want is not None and d.role != want:
                continue
            if implemented_only and not d.implemented:
                continue
            out.append(d)
        return sorted(out, key=lambda x: x.detector_type.value)

    def primary_types(self) -> Tuple[DetectorType, ...]:
        return tuple(
            d.detector_type
            for d in self.list_descriptors(role=EvidenceRole.PRIMARY_DETECTION)
        )

    def supporting_types(self) -> Tuple[DetectorType, ...]:
        return tuple(
            d.detector_type
            for d in self.list_descriptors(role=EvidenceRole.SUPPORTING_EVIDENCE)
        )

    def context_types(self) -> Tuple[DetectorType, ...]:
        return tuple(
            d.detector_type
            for d in self.list_descriptors(role=EvidenceRole.CONTEXT_ONLY)
        )

    def adapter_for(self, detector_type: DetectorType) -> Optional[AdapterFn]:
        return self._adapters.get(detector_type.value)

    # ── bounded evidence store ───────────────────────────────────────────

    @staticmethod
    def _slot_key(entity_key: str, detector: DetectorType) -> str:
        return f"{entity_key}::{detector.value}"

    def put(
        self,
        *,
        result: Optional[DetectorResult] = None,
        correlation: Optional[CorrelationResult] = None,
        entity_key: Optional[str] = None,
        switch_id: Optional[int] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        in_port: Optional[int] = None,
        role: Optional[EvidenceRole] = None,
        now: Optional[datetime] = None,
        meta: Optional[Dict] = None,
        evidence_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """
        Insert or replace evidence for (entity, detector).

        Same entity+detector supersedes the previous record (deterministic).
        When over ``max_records``, evict oldest insertion-order entries.
        """
        if result is None and correlation is None:
            raise ValueError("put() requires result and/or correlation")

        received = ensure_utc(now or utc_now())
        if result is not None:
            detector = result.detector
            observed = result.timestamp
        else:
            detector = DetectorType.CORRELATION
            observed = correlation.timestamp  # type: ignore[union-attr]

        ekey = entity_key_from(
            entity_key=entity_key,
            switch_id=switch_id,
            src_mac=src_mac,
            dst_mac=dst_mac,
            in_port=in_port,
        )
        resolved_role = normalize_role(role) or self.role_of(detector)
        if resolved_role is None:
            resolved_role = (
                EvidenceRole.SUPPORTING_EVIDENCE
                if detector is DetectorType.CORRELATION
                else EvidenceRole.CONTEXT_ONLY
            )

        record = EvidenceRecord(
            evidence_id=evidence_id or new_id(),
            entity_key=ekey,
            detector=detector,
            role=resolved_role,
            observed_at=observed,
            received_at=received,
            result=result,
            correlation=correlation,
            meta=dict(meta or {}),
        )
        slot = self._slot_key(ekey, detector)
        if slot in self._store:
            del self._store[slot]
        self._store[slot] = record
        self._enforce_bound()
        return record

    def _enforce_bound(self) -> None:
        while len(self._store) > max(1, int(self.max_records)):
            self._store.popitem(last=False)

    def get_current(
        self,
        detector: DetectorType,
        *,
        entity_key: Optional[str] = None,
        switch_id: Optional[int] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
    ) -> Optional[EvidenceRecord]:
        ekey = entity_key_from(
            entity_key=entity_key,
            switch_id=switch_id,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )
        return self._store.get(self._slot_key(ekey, detector))

    def list_evidence(
        self,
        *,
        entity_key: Optional[str] = None,
        detector: Optional[DetectorType] = None,
        role: Optional[EvidenceRole] = None,
        fresh_within_seconds: Optional[float] = None,
        now: Optional[datetime] = None,
    ) -> List[EvidenceRecord]:
        """Filter current store (after optional freshness window)."""
        want_role = normalize_role(role) if role is not None else None
        ekey = None
        if entity_key is not None:
            ekey = entity_key_from(entity_key=entity_key)
        max_age = (
            self.default_freshness_seconds
            if fresh_within_seconds is None and False
            else fresh_within_seconds
        )
        # Only apply freshness when caller asks (explicit None = no filter)
        clock = ensure_utc(now or utc_now()) if max_age is not None else None
        out: List[EvidenceRecord] = []
        for rec in self._store.values():
            if ekey is not None and rec.entity_key != ekey:
                continue
            if detector is not None and rec.detector != detector:
                continue
            if want_role is not None and rec.role != want_role:
                continue
            if max_age is not None and clock is not None:
                age = (clock - rec.observed_at).total_seconds()
                if age > float(max_age):
                    continue
            out.append(rec)
        return out

    def filter_fresh(
        self,
        *,
        max_age_seconds: Optional[float] = None,
        now: Optional[datetime] = None,
        entity_key: Optional[str] = None,
        detector: Optional[DetectorType] = None,
    ) -> List[EvidenceRecord]:
        return self.list_evidence(
            entity_key=entity_key,
            detector=detector,
            fresh_within_seconds=(
                self.default_freshness_seconds
                if max_age_seconds is None
                else max_age_seconds
            ),
            now=now,
        )

    def expire_stale(
        self,
        *,
        max_age_seconds: Optional[float] = None,
        now: Optional[datetime] = None,
    ) -> int:
        """Remove records older than freshness window. Returns count removed."""
        age_limit = (
            self.default_freshness_seconds
            if max_age_seconds is None
            else float(max_age_seconds)
        )
        clock = ensure_utc(now or utc_now())
        remove: List[str] = []
        for slot, rec in self._store.items():
            if (clock - rec.observed_at).total_seconds() > age_limit:
                remove.append(slot)
        for slot in remove:
            del self._store[slot]
        return len(remove)

    def size(self) -> int:
        return len(self._store)

    def clear_evidence(self) -> None:
        self._store.clear()

    def snapshot(self) -> Sequence[EvidenceRecord]:
        return tuple(self._store.values())

    def summary(self) -> Dict[str, object]:
        return {
            "detectors": [
                {
                    "type": d.detector_type.value,
                    "role": d.role.value,
                    "reliability": d.reliability,
                    "implemented": d.implemented,
                    "name": d.name,
                }
                for d in self.list_descriptors()
            ],
            "roles": dict(ROLE_RATIONALE),
            "store": {
                "size": self.size(),
                "max_records": self.max_records,
                "default_freshness_seconds": self.default_freshness_seconds,
            },
            "fusion_engine": "NOT_IN_R6_1",
            "production_integration": "NO",
            "output_contract": "shared_contracts.FusedDecision (R6.2+)",
            "input_contracts": [
                "shared_contracts.DetectorResult",
                "shared_contracts.DetectionEvent",
                "shared_contracts.CorrelationResult (native supporting)",
            ],
        }


def build_default_registry(
    *,
    max_records: int = DEFAULT_MAX_RECORDS,
    default_freshness_seconds: float = DEFAULT_FRESHNESS_SECONDS,
) -> EvidenceRegistry:
    """Repository-grounded default registry (SSL slot reserved, not active)."""
    from fusion import adapters as A

    reg = EvidenceRegistry(
        max_records=max_records,
        default_freshness_seconds=default_freshness_seconds,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.ML,
            role=EvidenceRole.PRIMARY_DETECTION,
            name="ML Anomaly Detector (IF+DT ensemble)",
            reliability=1.00,
            notes="AnomalyDetector.predict — Isolation Forest embedded, not separate.",
        ),
        adapter=A.adapt_ml_prediction,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.ENTROPY,
            role=EvidenceRole.PRIMARY_DETECTION,
            name="Entropy Detector",
            reliability=0.95,
            notes="EntropyDetector.analyze — PRIMARY ALERT/WARNING/NORMAL.",
        ),
        adapter=A.adapt_entropy_metrics,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.CORRELATION,
            role=EvidenceRole.SUPPORTING_EVIDENCE,
            name="R4 Cross-Layer Correlation",
            reliability=0.70,
            notes="CorrelationResult retained natively; DetectorResult view is supporting only.",
        ),
        adapter=A.adapt_correlation_result,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.ADWIN,
            role=EvidenceRole.CONTEXT_ONLY,
            name="ADWIN Drift",
            reliability=0.55,
            notes="Distribution change context — not DDoS by itself.",
        ),
        adapter=A.adapt_adwin_alerts,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.HDBSCAN,
            role=EvidenceRole.CONTEXT_ONLY,
            name="HDBSCAN Clustering",
            reliability=0.55,
            notes="Behavioural outlier/cluster context — not DDoS by itself.",
        ),
        adapter=A.adapt_hdbscan_summary,
    )
    reg.register(
        DetectorDescriptor(
            detector_type=DetectorType.SSL,
            role=EvidenceRole.PRIMARY_DETECTION,
            name="SSL Zero-Day (future R2)",
            reliability=0.90,
            notes="Reserved PRIMARY slot; adapter returns UNAVAILABLE until R2.",
            implemented=False,
        ),
        adapter=A.adapt_ssl_unavailable,
    )
    return reg
