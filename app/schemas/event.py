from typing import Optional
from pydantic import model_validator, BaseModel

from app.schemas.wire import WireModel


# Valorile acceptate pentru hash_status. 'ok' e singura care poate insoti un
# sha256. Restul numesc motivul absentei lui, nu doar o absenta tacuta:
#   unstable          — plafonul de asteptare a stabilizarii a fost depasit
#   unreadable        — fisierul n-a putut fi citit (lock, permisiuni)
#   too_large         — fisierul depaseste max_hash_bytes, nu s-a incercat hashing
#   vanished          — fisierul a disparut intre detectie si hashing
#   skipped_capacity  — coada de hashing era plina (v4)
#   skipped_shutdown  — agentul se oprea, bugetul de hashing a expirat (v4)
#
# Ultimele doua descriu AGENTUL, nu fisierul. 'unstable' spune ca fisierul nu
# s-a linistit; 'skipped_*' spun ca observatorul era sub presiune sau se oprea,
# in timp ce fisierul putea fi perfect stabil. Confundate, registrul de
# divulgare de la Etapa 3 nu ar mai putea separa costul impus de obiectul
# observat de costul impus de observator. Numele oglindesc deliberat
# SettleTracker.PendingFile.forced_reason din agent ('capacity', 'shutdown').
VALID_HASH_STATUSES = frozenset(
    {
        "ok",
        "unstable",
        "unreadable",
        "too_large",
        "vanished",
        "skipped_capacity",
        "skipped_shutdown",
    }
)


# Forma unui sha256 pe fir: exact 64 de caractere hexazecimale.
#
# De ce lungimea se verifica pe SIR si alfabetul explicit, in loc sa se incerce
# pur si simplu bytes.fromhex: metoda aceea IGNORA spatiile albe ASCII. Un sir
# de 66 de caractere cu doua spatii inauntru se decodeaza fara sa se planga in
# 32 de octeti perfect valizi, deci un hash rupt de un builder care concateneaza
# gresit ar trece de granita si ar consulta depozitul cu alt hash decat cel al
# fisierului. Lungimea sirului e singurul loc in care greseala aia se vede.
SHA256_HEX_LENGTH = 64
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class EventMeasurements(WireModel):
    """
    Costul observatiei, nu al obiectului observat.

    Separat structural de EventCreateRequest ca sa nu se amestece niciodata cu
    campurile care descriu fisierul (sha256, file_size): niciun camp de aici
    nu are voie sa intre intr-o decizie de verdict sau de escaladare — vezi
    contracts/wire-contract.json, models.event_measurements.
    """

    settle_wait_ms: Optional[int] = None
    hash_duration_ms: Optional[int] = None


# Treptele protocolului de divulgare progresiva. Ordinea e semnificativa:
# fiecare treapta divulga strict mai mult decat precedenta.
#   T0 — amprenta si metadate; niciun octet de continut
#   T1 — vector de trasaturi calculat local; tot niciun octet de continut
#   T2 — regiuni selective din fisier
#   T3 — fisierul integral
#
# Declarate toate acum, desi doar T0 exista: valorile viitoare intr-un
# vocabular inchis nu costa nimic, iar un server care le refuza ar bloca
# agentul exact in momentul in care treapta noua devine functionala.
VALID_DISCLOSURE_TIERS = frozenset({"T0", "T1", "T2", "T3"})

# La ce trepte continutul fisierului NU are voie sa fi plecat. Nu e o
# conventie de raportare, e definitia treptelor: daca T0 ar putea purta
# octeti de continut, distinctia dintre trepte s-ar dizolva, iar metrica de
# divulgare ar masura o scara fara semnificatie.
_CONTENTLESS_TIERS = frozenset({"T0", "T1"})


class EventDisclosure(WireModel):
    """
    Ce a parasit endpoint-ul, ca proprietate semantica a divulgarii.

    Separat de EventMeasurements din acelasi motiv pentru care acela a fost
    separat de corpul evenimentului la v3: unul spune ce a COSTAT observarea
    (settle_wait_ms, hash_duration_ms), celalalt spune ce A PLECAT. Granita e
    impusa de forma, nu de conventie.

    Nu poarta dimensiunea plicului. Un camp care ar numara octetii mesajului
    in care se afla si-ar schimba propria valoare la inserare — problema e
    circulara prin constructie, nu prin implementare. Contabilitatea plicului
    traieste deci in anteturi, ca autentificarea: vezi contracts/METRICS.md §7.

    tier e OBLIGATORIU in interiorul blocului, desi blocul insusi ramane
    optional. Cele doua reguli nu se bat cap in cap, ci impart raspunderea:
    absenta blocului e permisa tocmai ca un agent de dinainte de v5 sa nu
    primeasca 422 si sa-si piarda evenimentul din spool, dar un bloc PREZENT
    fara treapta ar readuce, cu un nivel mai jos, exact ambiguitatea pe care
    bicondiționalitatea a fost introdusa s-o elimine: nu s-ar mai putea spune
    daca evenimentul nu e pe scara, daca emitatorul e partial, sau daca
    builder-ul a uitat campul. Un agent care nu emite nimic ramane acceptat;
    doar unul care emite un bloc fara continut informational e respins.
    """

    tier: str
    content_bytes: Optional[int] = None

    @model_validator(mode="after")
    def _validate_tier(self) -> "EventDisclosure":
        if self.tier not in VALID_DISCLOSURE_TIERS:
            raise ValueError(
                f"tier invalid: {self.tier!r}. "
                f"Valori acceptate: {sorted(VALID_DISCLOSURE_TIERS)}."
            )

        if self.content_bytes is not None and self.content_bytes < 0:
            raise ValueError(
                f"content_bytes nu poate fi negativ: {self.content_bytes}."
            )

        if (
            self.tier in _CONTENTLESS_TIERS
            and self.content_bytes is not None
            and self.content_bytes > 0
        ):
            raise ValueError(
                f"tier este {self.tier!r} dar content_bytes este "
                f"{self.content_bytes}. Treptele T0 si T1 nu divulga continut "
                f"prin definitie; un numar pozitiv aici inseamna ori un bug de "
                f"atribuire, ori un canal necontabilizat."
            )

        return self


class EventCreateRequest(WireModel):
    agent_id: str
    event_type: str
    client_event_id: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    hash_status: Optional[str] = None
    file_size: Optional[int] = None
    measurements: Optional[EventMeasurements] = None
    disclosure: Optional[EventDisclosure] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    agent_instance_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_hash_invariants(self) -> "EventCreateRequest":
        """
        Impune DOAR invariantele care nu pot fi incalcate de traficul de azi.

        hash_status obligatoriu-cand-file_path-e-prezent NU e verificat aici,
        deliberat: agentul curent trimite file_path fara hash_status,
        iar o exceptie ridicata aici ar deveni 422 ->
        FatalTransportError -> EventDispatcher trateaza evenimentul ca poison
        message si il sterge din spool. Un camp lipsa e recuperabil; un
        eveniment sters, nu. Vezi app/schemas/wire.py pentru acelasi
        rationament aplicat cheilor nedeclarate. Invarianta e verificata in
        schimb la nivel de test, impotriva builder-ului agentului
        (test_event_contract.py::
        test_agent_builder_always_declares_hash_status_when_file_path_is_present),
        si va deveni validator aici cand agentul chiar calculeaza hash-uri.

        Aceeasi rezerva se aplica bicondiționalitatii introduse la v5:
        'disclosure prezent <=> file_path prezent'. Agentul curent inca nu
        emite blocul, deci un validator aici ar sterge din spool exact
        evenimentele pe care metrica de trepte exista sa le numere. Se
        verifica prin test impotriva builder-ului agentului, si devine
        validator cand agentul il emite — la fel cum s-a intamplat cu
        hash_status intre v3 si v4.
        """
        if self.hash_status is not None and self.hash_status not in VALID_HASH_STATUSES:
            raise ValueError(
                f"hash_status invalid: {self.hash_status!r}. "
                f"Valori acceptate: {sorted(VALID_HASH_STATUSES)}."
            )

        has_hash = self.sha256 is not None
        is_ok = self.hash_status == "ok"

        if has_hash and not is_ok:
            raise ValueError(
                "sha256 este prezent dar hash_status nu este 'ok'. Invarianta "
                "contractului: sha256 prezent <=> hash_status == 'ok' (vezi "
                "contracts/wire-contract.json, models.event_create_request)."
            )

        if is_ok and not has_hash:
            raise ValueError(
                "hash_status este 'ok' dar sha256 lipseste. Invarianta "
                "contractului: sha256 prezent <=> hash_status == 'ok'."
            )

        if is_ok and self.file_size is None:
            raise ValueError(
                "hash_status este 'ok' dar file_size lipseste. file_size "
                "trebuie sa insoteasca intotdeauna un hash reusit — e "
                "numaratorul metricii de octeti divulgati vs. always-upload, "
                "si nu se poate reconstrui retroactiv daca fisierul se schimba."
            )

        # Forma hash-ului (v7). Se verifica AICI, nu in ruta si nu in serviciul
        # care consulta reputatia: un singur loc decide ce e un sha256 valid,
        # iar locul ala e langa invarianta care spune cand are voie sa existe.
        #
        # 422 e raspunsul corect, si nu deschide o clasa noua de esec: campul
        # producea deja 422 prin bicondiționalitatea de mai sus. Rezerva
        # poison-message din docstring nu se aplica — acolo agentul curent omitea
        # legitim un camp, aici niciun agent corect nu poate emite hex invalid.
        # Un hex rupt e o minciuna de contract, nu incertitudine; incertitudinea
        # are deja vocabular propriu, in hash_status.
        if has_hash:
            hexa = self.sha256

            if len(hexa) != SHA256_HEX_LENGTH or not set(hexa) <= _HEX_DIGITS:
                raise ValueError(
                    f"sha256 nu e hexazecimal de {SHA256_HEX_LENGTH} de "
                    f"caractere: {hexa!r} ({len(hexa)} caractere). Depozitul de "
                    f"reputatie primeste 32 de octeti bruti, decodati din sirul "
                    f"asta o singura data, la granita — un sir care nu se poate "
                    f"decoda ar consulta depozitul cu alt hash decat al "
                    f"fisierului, sau deloc."
                )

            # Canonicalizare la granita, nu toleranta ascunsa.
            #
            # Majusculele sunt acelasi sha256 scris altfel, nu o eroare: un 422
            # aici ar sterge din spool un eveniment perfect corect, ceea ce e
            # exact costul refuzat la v3 si v5. Dar sirul se si STOCHEAZA asa cum
            # a venit, iar prevalenta se numara pe hash-uri DISTINCTE — doua
            # scrieri ale aceluiasi hash ar deveni doua fisiere in cifra aia,
            # fara nicio eroare vizibila. Depozitul de reputatie a inchis exact
            # gaura asta stocand 32 de octeti bruti in loc de text; aici, unde
            # textul ramane text, canonicalizarea face aceeasi treaba.
            self.sha256 = hexa.lower()

        return self


class EventResponse(BaseModel):
    """
    Evenimentul stocat, asa cum pleaca inapoi spre agent.

    Nu mosteneste WireModel, si asta nu e o scapare: aici serverul e EMITENTUL,
    iar un camp in plus e o alegere a noastra, nu o surpriza venita de pe retea
    (vezi app/schemas/wire.py). Ce apara WireModel — cheia nedeclarata care intra
    tacut — nu exista pe directia asta.

    `run_id` a fost adaugat la contract_version 6, nu inventat atunci: ruta il
    trimitea de la 1.4.2 incoace, iar modelul nu-l declara. Cat timp modelul era
    cod mort, absenta n-a costat nimic. Adoptat fara el, ar fi STERS campul de pe
    fir — un model de raspuns filtreaza, nu completeaza. Golul e pazit acum de
    test_event_contract.py::test_event_response_declares_every_stored_field.

    Ordinea campurilor o repeta pe cea a dictionarului construit in
    event_service.create_event, cu `event_id` la urma din exact motivul pentru
    care event_store._row_to_event il pune acolo: ordinea cheilor nu schimba
    nicio cifra, dar schimba diff-ul oricarui raspuns comparat cu unul vechi.
    Commit-ul care a adoptat modelul promite ca niciun octet de pe fir nu se
    schimba; promisiunea e verificabila doar daca ordinea se pastreaza.
    """

    agent_id: str
    agent_instance_id: Optional[str] = None
    event_type: str
    client_event_id: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    hash_status: Optional[str] = None
    file_size: Optional[int] = None
    measurements: Optional[EventMeasurements] = None
    disclosure: Optional[EventDisclosure] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    received_at: Optional[str] = None
    run_id: str
    status: str
    event_id: int


class EventCreateResponse(BaseModel):
    """
    Raspunsul la POST /api/events. Prima declarare a directiei descendente.

    Pana la contract_version 6, ruta intorcea un dictionar construit pe loc:
    `next_action` era un camp de fir pe care niciun contract nu-l cunostea, iar
    EventResponse era cod mort. Directia server -> agent nu are echivalent de
    WireModel — agentul citeste raspunsul cu dict.get(), deci un camp redenumit
    pe server nu produce nicio eroare, ci un None ignorat. E aceeasi gaura pe
    care contractul o descrie la heartbeat_response, doar ca acolo exista macar
    un contract deasupra.

    Se declara ACUM, inainte sa poarte ceva: P2.3 pune aici dispozitia de treapta
    produsa de depozitul de reputatie. Un canal care capata primul mecanism
    vizibil al protocolului inainte de contract e un canal in care redenumirea se
    descopera in celalalt repo, peste luni.

    `next_action` ramane "none" si ramane o DIRECTIVA — ce trebuie facut. Ce vine
    la P2.3 e o DISPOZITIE — ce se stie la adancimea T0. Confundate, ar exista
    doua mecanisme de decizie in acelasi raspuns, iar banda de incertitudine
    (§L2.7) ar fi contrazisa pe tacute de un camp care nu-i apartine.
    """

    message: str
    event: EventResponse
    next_action: str