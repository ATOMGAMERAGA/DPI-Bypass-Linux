"""Aday tabanlı, ölçümlü ve tamamen geri alınabilir düşük gecikme motoru.

Tasarım
-------
Tek bir ayarı uygulayıp "ping düştü" demek yerine motor şunu yapar::

    hedefleri çöz ve yolu doğrula
      → aday A: A ölç · uygula · B ölç · geri al · … (ABBA blokları)
      → aday B: aynısı
      → blok bootstrap ile istatistiksel karar
      → kazananı BAĞIMSIZ holdout bloklarıyla yeniden doğrula
      → doğrulandıysa uygula, doğrulanmadıysa geri al

Adaylar donanıma ve bağlantı türüne göre üretilir. Yalnızca bu sistemde
teknik olarak anlamı olan, okunabilir ve geri yüklenebilir çalışma zamanı
ayarları aday olur:

* Wi-Fi güç tasarrufu (``iw dev … set power_save off``) — uyku/uyanma
  gecikmesini kaldırır.
* Kuyruk disiplini (``fq_codel`` / ``fq`` / ``cake``) — yalnızca mevcut
  yapının geri alma tarifi **kanıtlandıysa**. ``mq`` kökü korunur, tanınan
  yaprakları aday olur. Kullanıcının CAKE/HTB/SQM yapılandırması ezilmez.
* Ethernet'te EEE ve RX interrupt coalescing — sürücü gerçekten
  destekliyorsa; uygulanan değer geri okunarak doğrulanır.
* **Opt-in** yük altında düşük gecikme kipi (SQM): gerçek ``bandwidth``
  değeriyle CAKE (ya da HTB+fq_codel) ve mümkünse IFB ingress shaping.

Bilerek **yapılmayanlar**: DNS değiştirme, rota/MTU/IPv6 oynaması, kalıcı
sysctl yazımı, TCP tıkanıklık denetimi (BBR) seçimi, ``tcp_low_latency``
gibi etkisiz legacy anahtarlar, güvenlik duvarı kuralı, GRO/TSO/IRQ/governor
toplu değişikliği. Bunların hiçbiri bir oyunun UDP RTT'sini düşürmez.

Ölçüm
-----
Her ölçüm noktası endpoint **bazında** özetlenir: farklı hedeflerin örnekleri
asla tek havuzda birleştirilmez. Toplu gösterge sabit ağırlıklıdır, yani bir
hedefin çok, diğerinin az yanıt vermesi sahte kazanç üretemez. Karar,
eşleştirilmiş A/B blokları ve blok bootstrap güven aralığıyla verilir;
kontrol-kontrol gürültü tabanı hem kazanç hem kötüleşme kararını kapılar.

Gerçek bufferbloat ölçümü bağlantıyı doyurmayı gerektirir. Bu yalnız
kullanıcının açık onayıyla, kendi sunucusuna karşı ve sert bütçe altında
yapılır; yapılmadıysa "bufferbloat ölçüldü" denmez.
"""

from __future__ import annotations

from .actions import (ActionError, ActionExecutor, ActionSnapshot,  # noqa: F401
                      LatencySnapshot, SnapshotCorrupt, coalesce_candidates,
                      parse_coalesce)
from .analysis import (ComparisonResult, MetricDelta,  # noqa: F401
                       OUTCOME_GAIN, OUTCOME_INCOMPARABLE,
                       OUTCOME_INCONCLUSIVE, OUTCOME_NO_GAIN,
                       OUTCOME_REGRESSION, bootstrap_ci, compare,
                       control_noise, gain_dict, summarize_endpoints)
from .engine import (BUSY_STATES, CANDIDATE_BUDGET,  # noqa: F401
                     CANDIDATE_CANCELLED, CANDIDATE_FAILED,
                     CANDIDATE_NOT_NEEDED, CANDIDATE_REJECTED,
                     CANDIDATE_TRIED, CANDIDATE_UNSUPPORTED, Candidate,
                     CandidateResult, Environment, LatencyError,
                     LatencyOptimizer, LatencySettings, LatencyStatus,
                     STATE_ACTIVE, STATE_ALREADY, STATE_APPLYING,
                     STATE_BENCHMARKING, STATE_CANCELLED, STATE_DISABLED,
                     STATE_EXTERNAL, STATE_FAILED, STATE_INCONCLUSIVE,
                     STATE_MEASURED, STATE_MEASURING, STATE_NO_GAIN,
                     STATE_PERMISSION, STATE_ROLLBACK_FAILED,
                     STATE_ROLLED_BACK, STATE_SNAPSHOT_CORRUPT,
                     STATE_UNSUPPORTED, STATE_VERIFYING, Step)
from .load import (LoadBudget, LoadError, LoadGenerator,  # noqa: F401
                   LoadResult, LoadTarget)
from .metrics import (CONDITION_IDLE, CONDITION_LOAD_BOTH,  # noqa: F401
                      CONDITION_LOAD_DOWN, CONDITION_LOAD_UP,
                      CONDITION_FIRST_PACKET, CONDITION_NATURAL, CONDITIONS,
                      EndpointSamples, EndpointSpec, EndpointStats,
                      LatencyMeasurement, LatencyStats, METHOD_ICMP,
                      METHOD_TCP_CONNECT, METHOD_TLS_HANDSHAKE,
                      METHOD_UDP_ECHO, ROLE_GATEWAY, ROLE_REFERENCE, ROLE_USER)
from .probe import (LatencyProbe, PathInfo, PathResolver,  # noqa: F401
                    ProbePlan, TargetResolver, TargetSpec, build_plan,
                    parse_ping, reference_targets)
from .profiles import LatencyProfiles, ProfileContext  # noqa: F401
from .qdisc import (QdiscNode, QdiscSlot, QdiscTopology,  # noqa: F401
                    QDISC_TARGETS, read_topology)
from .sqm import (IFB_DEVICE, SqmCapacity, SqmError,  # noqa: F401
                  SqmManager, SqmState)

__all__ = [
    "ActionError", "ActionExecutor", "ActionSnapshot", "BUSY_STATES",
    "Candidate", "CandidateResult", "ComparisonResult", "Environment",
    "EndpointSamples", "EndpointSpec", "EndpointStats", "LatencyError",
    "LatencyMeasurement", "LatencyOptimizer", "LatencyProbe",
    "LatencyProfiles", "LatencySettings", "LatencySnapshot", "LatencyStats",
    "LatencyStatus", "LoadBudget", "LoadGenerator", "LoadTarget",
    "MetricDelta", "PathInfo", "PathResolver", "ProbePlan", "ProfileContext",
    "QdiscSlot", "QdiscTopology", "SnapshotCorrupt", "SqmCapacity",
    "SqmManager", "SqmState", "Step", "TargetResolver", "TargetSpec",
    "build_plan", "compare", "parse_ping", "reference_targets",
]
