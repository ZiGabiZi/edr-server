"""
Alarma de discrepanță: când tăcerea metricii nu mai e de ajuns.
===============================================================

De ce nu se poate copia de la AuthFailureAlarm (edr-agent/services/auth_alarm.py):
    Alarma de autentificare trăiește pe agent și se declanșează pe un eveniment
    discret — o cerere a eșuat. Numeri eșecuri consecutive, măsori timpul scurs,
    ridici tonul.

    Discrepanța n-are eveniment. E o diferență între două numere care se
    compară abia când vine o cerere nouă. Nu poți număra „eșecuri consecutive",
    pentru că nu eșuează nimic: pur și simplu două contoare nu se potrivesc.

    De aici vine forma: nu se numără repetări, se verifică o stare la fiecare
    cerere, iar ce se limitează în timp e **emiterea**, nu declanșarea.

De ce mai e nevoie de alarmă, când metrica raportează deja discrepanța:
    O cifră într-un răspuns HTTP se vede doar dacă cineva se uită. Un
    `above_upper_bound` peste prag înseamnă ori că altcineva trimite în numele
    agentului, ori că există un canal pe care agentul nu-l contabilizează —
    prima e o problemă de securitate, a doua invalidează numărătorul afirmației
    centrale. Niciuna nu are voie să aștepte până se uită cineva la o metrică.

De ce se emite rar:
    O verificare la fiecare cerere, cu emitere la fiecare cerere, ar scrie
    aceeași linie de sute de ori pe minut. Un log care se repetă la nesfârșit e
    un log pe care înveți să-l filtrezi, iar atunci alarma a dispărut fără să
    fie ștearsă. Se emite cel mult o dată la interval, per încarnare și per
    direcție — același tipar de alarmă recurentă folosit la autentificare.

    Per DIRECȚIE, nu doar per încarnare: dacă o încarnare trece de la o margine
    la cealaltă, a doua e o știre, nu o repetare. Direcțiile nu se acoperă una
    pe alta.
"""

import logging
import time
from threading import Lock
from typing import Callable, Dict, Optional, Tuple

from app.services import wire_accounting
from app.services.wire_accounting import IncarnationAccount


logger = logging.getLogger(__name__)


DEFAULT_REPEAT_ALARM_SECONDS = 300.0  # ~5 minute


class WireDiscrepancyAlarm:
    """
    Emite în jurnal discrepanțele care trec de pragul din METRICS.md §7.3.

    Ceasul e injectabil, ca la AuthFailureAlarm, iar motivul e același: fără el,
    un test al limitării în timp ar trebui să aștepte minute reale. `monotonic`,
    nu wall-clock — o ajustare de oră sau un salt de fus n-au ce căuta într-o
    decizie despre cât de des vorbim.

    Praguri nu ține: le calculează wire_accounting.threshold_breach(), aceeași
    funcție pe care o publică metrica. Dacă alarma ar avea pragurile ei, log-ul
    și `/api/metrics/disclosure` ar putea spune lucruri diferite despre aceeași
    încarnare, iar cine le compară n-ar ști pe care să creadă.
    """

    def __init__(
        self,
        repeat_alarm_seconds: float = DEFAULT_REPEAT_ALARM_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repeat_alarm_seconds = repeat_alarm_seconds
        self._clock = clock
        self._lock = Lock()
        # (agent_id, agent_instance_id, direcție) -> momentul ultimei emiteri
        self._last_emitted: Dict[Tuple[str, str, str], float] = {}

    def observe(
        self,
        agent_id: str,
        agent_instance_id: str,
        account: IncarnationAccount,
    ) -> Optional[Dict[str, object]]:
        """
        Verifică starea încarnării și emite dacă e cazul.

        Întoarce depășirea emisă, sau None — fie pentru că nu e nicio depășire,
        fie pentru că a fost deja emisă recent. Apelantul nu face nimic cu
        valoarea; există pentru teste, ca limitarea în timp să fie verificabilă
        fără să citească fișiere de log.
        """
        breach = wire_accounting.threshold_breach(account)

        if breach is None:
            return None

        key = (agent_id, agent_instance_id, str(breach["verdict"]))
        now = self._clock()

        with self._lock:
            last = self._last_emitted.get(key)

            if last is not None and now - last < self._repeat_alarm_seconds:
                return None

            self._last_emitted[key] = now

        self._emit(agent_id, agent_instance_id, breach)

        return breach

    def _emit(
        self,
        agent_id: str,
        agent_instance_id: str,
        breach: Dict[str, object],
    ) -> None:
        """
        Scrie linia de jurnal, cu ambele numere și cu direcția pe față.

        Nivelul e ERROR pentru amândouă direcțiile, dar textul nu e același:
        `above_upper_bound` numește explicit cele două explicații posibile,
        pentru că cine citește la trei dimineața n-are timp să reconstruiască
        din cifre ce înseamnă că serverul a primit mai mult decât s-a trimis.
        """
        if breach["verdict"] == wire_accounting.VERDICT_ABOVE:
            explanation = (
                "the server received MORE than the agent reports sending: either "
                "something is sending in this agent's name, or the agent has an "
                "unaccounted channel"
            )
        else:
            explanation = (
                "the agent reports more delivered than the server received: "
                "accounting is broken on one side or the other"
            )

        logger.error(
            "Wire discrepancy for agent '%s' incarnation '%s': %s (%s). "
            "Gap %s bytes, over both thresholds (%s bytes = %s typical messages, "
            "%s bytes = share of measured volume).",
            agent_id,
            agent_instance_id,
            breach["verdict"],
            explanation,
            breach["gap_bytes"],
            breach["message_threshold_bytes"],
            wire_accounting.IN_FLIGHT_MESSAGE_ALLOWANCE,
            breach["volume_threshold_bytes"],
        )

    def reset_for_tests(self) -> None:
        with self._lock:
            self._last_emitted.clear()


# Alarma procesului. Ca la registrul agentului: un proces server e o instanță,
# iar limitarea în timp trebuie să fie comună tuturor cererilor lui, altfel
# fiecare cerere și-ar avea propriul „am mai spus asta recent" și n-ar limita
# nimic.
_alarm = WireDiscrepancyAlarm()


def get_wire_alarm() -> WireDiscrepancyAlarm:
    return _alarm


def reset_for_tests() -> None:
    _alarm.reset_for_tests()
