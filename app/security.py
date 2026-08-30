"""
Stratul HTTP al autentificării — traducerea identității în coduri de răspuns.
=============================================================================

Separarea față de app/services/auth_service.py e deliberată: acolo stă
depozitul de chei, care poate fi testat fără să existe un server; aici stă
singurul loc care decide ce cod HTTP vede agentul. Codul ăla nu e un detaliu
cosmetic — el determină ce face agentul cu evenimentele lui.

401 vs 403 — distincția care ține evenimentele în viață
-------------------------------------------------------
    401 = identitate nerecunoscută. Cheia lipsește, e greșită, a fost revocată
          sau depozitul serverului a fost golit. Poate fi adevărat acum și fals
          peste zece minute, din motive care n-au nicio legătură cu conținutul
          cererii: o rotație de cheie, o restaurare din backup, o greșeală de
          deploy. Agentul îl tratează ca stare temporară — păstrează coada și
          escaladează în log (services/auth_alarm.py din edr-agent).

    403 = identitate acceptată, acțiune refuzată. Cheia e validă, dar aparține
          altui agent decât cel numit în corp. Nu se repară de la sine, dar NU
          e o proprietate a evenimentului, ci a perechii cheie–configurare, deci
          nici aici evenimentele nu se aruncă.

Ce s-a schimbat față de comportamentul anterior:
    Agentul clasifica orice 4xx în afară de 404/408/429 drept FatalTransportError,
    iar EventDispatcher trata respingerea definitivă ca poison message și ștergea
    evenimentul din spool. Cu autentificarea pornită și cu vechea clasificare, o
    cheie greșită timp de cinci minute ar fi șters ireversibil tot ce era în
    coadă. Spool-ul persistent, construit ca să garanteze at-least-once, ar fi
    devenit at-most-once exact în intervalul în care ceva era stricat.

    De aceea 401 și 403 au acum excepții proprii pe agent (AuthenticationError,
    IdentityMismatchError), niciuna descinzând din FatalTransportError.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, status

from app.services import auth_service


logger = logging.getLogger(__name__)


# Modurile în care o înregistrare poate fi autorizată.
REGISTRATION_MODE_ENROLLMENT = "enrollment"
REGISTRATION_MODE_REREGISTRATION = "reregistration"


@dataclass(frozen=True)
class RegistrationAuthorization:
    """
    Cum a fost autorizată o înregistrare.

    Contează pentru apelant: doar înrolarea (secret de înrolare valid) emite o
    cheie nouă. O re-înregistrare autentificată cu cheia existentă păstrează
    cheia — altfel fiecare restart al serverului ar rota credențialele întregului
    parc, iar o rotație nu e un lucru care trebuie să se întâmple din reflex.
    """

    mode: str
    agent_id: str

    @property
    def issues_key(self) -> bool:
        return self.mode == REGISTRATION_MODE_ENROLLMENT


def authenticated_agent_id(
    x_agent_key: Optional[str] = Header(default=None),
) -> str:
    """
    Dependency FastAPI: întoarce agentul căruia îi aparține cheia prezentată.

    Ridică 401 dacă antetul lipsește sau cheia nu e recunoscută. NU verifică
    dacă identitatea corespunde corpului cererii — aceea e o a doua întrebare,
    pusă separat de require_identity_match(), pentru că are nevoie de corp.
    """
    agent_id = auth_service.agent_id_for_key(x_agent_key)

    if agent_id is None:
        # Deliberat fără detalii: mesajul nu spune dacă antetul lipsea, era
        # greșit sau fusese revocat. Un client legitim n-are ce face cu
        # diferența, iar unul care ghicește chei ar afla din ea exact ce caută.
        logger.warning(
            "Rejected a write request with an unrecognized or missing %s header.",
            auth_service.AGENT_KEY_HEADER,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unrecognized or missing agent API key",
            headers={"WWW-Authenticate": auth_service.AGENT_KEY_HEADER},
        )

    return agent_id


def require_operator_secret(
    x_enrollment_secret: Optional[str] = Header(default=None),
) -> None:
    """
    Dependency FastAPI: lasă să treacă numai cine deține secretul de înrolare.

    De ce o rută de operator are nevoie de pază, când GET /api/agents și
    GET /api/events n-au:
        Acelea sunt CITIRI, iar gaura lor e declarată și urmărită separat
        (edr-server#9). Deschiderea unei rulări de măsurătoare e o SCRIERE, și
        una de un fel aparte: nu adaugă date, ci schimbă înțelesul datelor care
        vin după ea. Cine poate reeticheta din exterior poate muta evenimentele
        unui experiment în corpusul altuia, iar rezultatul nu arată stricat —
        arată exact ca o măsurătoare, cu alte numere. Un mecanism construit
        tocmai ca cifrele să nu poată minți n-are voie să fie el însuși
        rescriabil de oricine deschide un socket.

    De ce secretul de ÎNROLARE și nu o credențială proprie:
        E singura credențială de nivel de operator pe care serverul o are azi.
        Reutilizarea e o alegere declarată, nu o scăpare, și are o limită reală:
        secretul se șterge de pe endpoint după prima folosire reușită (vezi
        auth_service), deci în practică rămâne la instalator, nu în parc. Un
        secret de analist, separat, e pasul care închide și cele trei rute de
        citire — o schimbare proprie, nu una strecurată aici.

    De ce nu cheia unui agent:
        Ar însemna că orice endpoint monitorizat poate renumi experimentul care
        îl măsoară. Partea măsurată nu decide cum se numește măsurătoarea.
    """
    if auth_service.verify_enrollment_secret(x_enrollment_secret):
        return

    logger.warning(
        "Rejected an operator request with an unrecognized or missing %s header.",
        auth_service.ENROLLMENT_SECRET_HEADER,
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="This route requires the operator (enrollment) secret",
        headers={"WWW-Authenticate": auth_service.ENROLLMENT_SECRET_HEADER},
    )


def require_identity_match(authenticated: str, claimed: str) -> None:
    """
    Verifică faptul că agentul autentificat este chiar cel numit în cerere.

    E pasul pe care e cel mai ușor să-l uiți și fără de care restul nu valorează
    mare lucru: fără el, toți agenții ar fi autentificați și oricare ar putea
    scrie evenimente în numele oricui. Un endpoint compromis ar putea fabrica
    activitate pe o altă mașină, iar registrul și mecanismul de prevalență ar
    prelua fabricația ca adevăr.
    """
    if authenticated == claimed:
        return

    logger.error(
        "Agent '%s' attempted to act as '%s'. Request refused.",
        authenticated,
        claimed,
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="The authenticated agent key does not belong to the agent_id in this request",
    )


def authorize_registration(
    claimed_agent_id: str,
    enrollment_secret: Optional[str],
    agent_key: Optional[str],
) -> RegistrationAuthorization:
    """
    Autorizează POST /api/agents/register pe două căi, în ordinea asta:

        1. secret de înrolare valid -> ÎNROLARE. Se emite o cheie nouă pentru
           agent_id-ul cerut. E calea de la instalare și, deliberat, și calea de
           recuperare după pierderea cheii de pe endpoint.

        2. cheie de agent validă, care aparține chiar agent_id-ului cerut ->
           RE-ÎNREGISTRARE. Nu se emite nimic; agentul își păstrează cheia.
           Fără calea asta, agenții n-ar putea răspunde directivei 'reregister'
           după un restart al serverului: secretul de înrolare a fost deja
           șters de pe endpoint după prima folosire.

    Orice altceva:
        - cheie validă, dar a altui agent -> 403 (identitate acceptată, acțiune
          refuzată). Tipic: fișierul de cheie al unei mașini copiat pe alta.
        - nimic valid -> 401.

    Ordinea contează. Secretul de înrolare se verifică primul, altfel un agent
    care își reînrolează o mașină cu o cheie veche încă validă n-ar mai primi
    niciodată una nouă.
    """
    if auth_service.verify_enrollment_secret(enrollment_secret):
        return RegistrationAuthorization(
            mode=REGISTRATION_MODE_ENROLLMENT,
            agent_id=claimed_agent_id,
        )

    authenticated = auth_service.agent_id_for_key(agent_key)

    if authenticated is None:
        logger.warning(
            "Rejected a registration attempt for agent '%s': neither a valid "
            "enrollment secret nor a known agent key was presented.",
            claimed_agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registration requires a valid enrollment secret or an existing agent key",
            headers={"WWW-Authenticate": auth_service.ENROLLMENT_SECRET_HEADER},
        )

    require_identity_match(authenticated, claimed_agent_id)

    return RegistrationAuthorization(
        mode=REGISTRATION_MODE_REREGISTRATION,
        agent_id=claimed_agent_id,
    )
