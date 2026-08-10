"""
Baza modelelor care intră de pe fir (agent -> server).

De ce există acest modul:
    Pydantic rulează implicit cu extra="ignore": o cheie pe care schema nu o
    declară era aruncată fără nicio urmă. Agentul primea 200 OK, serverul nu
    scria nimic în log, iar câmpul rămânea None. O literă greșită într-un builder
    (agent_instnce_id în loc de agent_instance_id) nu producea nicio eroare
    nicăieri — producea date lipsă, descoperite luni mai târziu, când cineva le
    căuta.

    contracts/wire-contract.json și test_wire_contract.py prind cazul ăsta la
    commit, în repo-ul care face greșeala. Modulul de față închide restul: un
    emitent care nu trece prin testele acelea (un build vechi rămas în parc, un
    curl scris de mână, un agent recompilat din altă ramură) nu mai poate greși
    tăcut. Cheia necunoscută apare o dată, cu numele ei, în logul serverului.

De ce nu extra="forbid":
    "forbid" pare răspunsul evident — respinge cererea cu 422 și greșeala devine
    imposibil de ratat. În sistemul ăsta însă, 422 nu e zgomot, ci oprire.
    Agentul clasifică orice 4xx în afară de 404/408/429 drept FatalTransportError
    (edr-agent/services/transport.py::handle_response), iar de acolo pleacă trei
    drumuri, toate mai grave decât un câmp None:

      - la heartbeat, heartbeat_loop() face return: agentul nu mai trimite
        niciun heartbeat până la repornirea procesului, iar endpoint-ul apare
        mort în consolă;
      - la /api/events, EventDispatcher tratează respingerea definitivă ca
        poison message și șterge evenimentul din spool — pierdere de date, nu
        doar un câmp gol;
      - la înregistrare, register_agent_with_retry() întoarce False, iar
        run_agent() sare peste bucla de heartbeat: agentul nu pornește deloc.

    Adică exact greșeala pe care "forbid" o face vizibilă ar opri monitorizarea
    mașinii. Un câmp necompletat e recuperabil; un agent tăcut, nu.

De ce curățăm extras după logare:
    Cu extra="allow", cheile necunoscute rămân pe model și intră în
    model_dump(). agent_service.register_agent() face
    existing_agent_by_id.update(agent_data), deci un agent_instance_id trimis
    din greșeală la înregistrare s-ar scrie în store și ar suprascrie baseline-ul
    incarnării înainte ca primul heartbeat să îl poată compara — fix invarianta
    pe care contractul o apără declarându-l 'forbidden' acolo, și fix regresia
    păzită de test_event_contract.py::test_registration_does_not_adopt_the_incarnation.

    Curățarea readuce semantica lui extra="ignore" pentru tot codul de după
    validare. Pe fir nu se schimbă nimic: cheile necunoscute erau aruncate și
    înainte. Se schimbă doar că acum se aude.
"""

import logging

from pydantic import BaseModel, ConfigDict, model_validator


logger = logging.getLogger(__name__)


class WireModel(BaseModel):
    """
    Model de cerere care loghează cheile nedeclarate, apoi le aruncă.

    Modelele de răspuns (server -> agent) NU au nevoie de bază: acolo serverul e
    emitentul, iar un câmp în plus e o alegere a noastră, nu o surpriză venită
    de pe rețea.
    """

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _log_and_drop_undeclared_fields(self) -> "WireModel":
        undeclared = self.__pydantic_extra__

        if undeclared:
            logger.warning(
                "%s a primit chei nedeclarate de contract: %s. Nu sunt persistate. "
                "Fie emitentul le-a scris greșit, fie schema a rămas în urma "
                "contractului (contracts/wire-contract.json).",
                type(self).__name__,
                sorted(undeclared),
            )
            undeclared.clear()

        return self
