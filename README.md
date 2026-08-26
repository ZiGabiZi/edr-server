# edr-server

Backend-ul care primește ce trimit agenții, decide **cui are voie să creadă**, și
măsoară **cât a costat** observarea.

Construit în FastAPI. Perechea lui:
[edr-agent](https://github.com/ZiGabiZi/edr-agent), care rulează pe endpoint și
decide ce merită trimis.

Lucrare de licență.

---

## API

| Rută | Metodă | Cere | Ce face |
|---|---|---|---|
| `/health` | GET | — | verificare de disponibilitate |
| `/api/agents/register` | POST | secret de înrolare **sau** cheie de agent | înrolează sau re-înregistrează, emite cheia |
| `/api/agents/{id}/heartbeat` | POST | cheia lui `{id}` | starea agentului, verdict de continuitate, directive |
| `/api/events` | POST | cheia agentului din corp | ingestie idempotentă de evenimente |
| `/api/agents` | GET | **nimic** | inventarul parcului |
| `/api/events` | GET | **nimic** | fluxul de evenimente |
| `/api/metrics/disclosure` | GET | **nimic** | raportul divulgare / always-upload |

Cele trei rute de citire sunt deliberat deschise în acest pas — analistul nu are
încă un secret propriu. E o gaură cunoscută, urmărită ca issue, nu o scăpare;
ce garantează totuși proiectarea e că prin ele **nu se scurg credențiale**.

Contractul complet al antetelor: [contracts/AUTH.md](contracts/AUTH.md).
Contractul corpurilor: [contracts/wire-contract.json](contracts/wire-contract.json).

---

## Serverul e frontiera de încredere

Agentul rulează pe o mașină care poate fi compromisă, iar „build vechi" și
„build modificat" produc intrări identice. Nicio invariantă importantă nu se
sprijină deci pe corectitudinea agentului.

### Autentificare legată de conținut

Fiecare scriere verifică două lucruri separate: că **cheia e cunoscută**, și că
ea aparține chiar `agent_id`-ului din corpul cererii. Al doilea pas e cel mai
ușor de uitat și fără el primul nu valorează mare lucru — altfel toți agenții
sunt autentificați și oricare poate scrie în numele oricui, iar un endpoint
compromis ar putea fabrica activitate pe altă mașină.

### Ordinea verificărilor e o decizie de securitate

Pe `/api/events`: identitate → legare cu corpul → abia apoi existența agentului.

Invers, diferența dintre `404` și `200` ar spune unui agent autentificat care
`agent_id`-uri există în parc — o rută de enumerare oferită tocmai celui care nu
are voie să știe.

### Codurile de răspuns sunt alese pentru ce face agentul cu ele

`401` identitate nerecunoscută, `403` identitate acceptată dar acțiune refuzată,
`409` nume revendicat de altă mașină, `422` payload invalid. Distincția nu e
cosmetică: agentul ia decizii ireversibile pe baza lor. Un `422` întors greșit îl
face să-și șteargă un eveniment din coadă; un `409` clasificat ca fatal îl făcea
să se oprească tăcut la pornire.

Mesajul de `401` nu spune dacă antetul lipsea, era greșit sau fusese revocat. Un
client legitim n-are ce face cu diferența; unul care ghicește chei ar afla din ea
exact ce caută.

### Cheile nu stau lângă agenți

Depozitul păstrează **SHA-256** al cheii, niciodată cheia. Verificarea nu are
nevoie de valoarea originală: se calculează amprenta celei prezentate și se
caută în dicționar, deci căutarea însăși e comparația.

Depozitul e ținut **separat** de registrul de agenți, din două motive
independente. Unul de confidențialitate: `GET /api/agents` e public, iar o cheie
scrisă în dicționarul agentului ar fi ajuns direct în răspunsul ei. Altul de
disponibilitate: registrul e volatil și se pierde la repornire, dar cheile sunt
persistate — dacă ar dispărea odată cu el, tot parcul ar rămâne blocat afară,
fiindcă agenții și-au consumat deja secretul de înrolare.

---

## Ce știe serverul despre un agent

### Trei axe de continuitate, deliberat neamestecate

| Semnal | De unde vine | Ce răspunde |
|---|---|---|
| **repornire** | `agent_instance_id` — incarnarea procesului | procesul agentului a repornit? |
| **ferestre ratate** | ceasul propriu al serverului (`last_seen`) | cât timp a fost endpoint-ul neacoperit? |
| **încercări eșuate** | contorul de secvență al agentului | câte heartbeat-uri n-au ajuns? |

Motivul separării: un singur contor purta înainte două semnale ortogonale — „a
repornit procesul" și „a sosit un pachet mai vechi" — iar ele arată identic dacă
privești un singur număr.

Iar durata **nu poate** fi derivată din secvență: încercările agentului sunt
rărite de backoff exponențial, deci golul de secvență descrie retry-urile, nu
timpul. La 10 secunde interval, o pană de 10 minute produce ~7 încercări față de
~86 de ferestre reale. Serverul are a doua mărime din surse proprii, fără să
ceară niciun câmp nou și fără să creadă ceasul endpoint-ului.

### Ingestie idempotentă

Retransmisiile aceluiași `client_event_id` nu creează duplicate — ceea ce face
livrarea *at-least-once* a agentului sigură de folosit.

---

## Măsurătoarea pe care o deține serverul

Agentul trimite amprente, nu conținut. Serverul e locul unde se poate spune
**cât a costat asta**, pentru că el are toate datele.

```
GET /api/metrics/disclosure
```

Pe măsurarea de referință — 444 de fișiere, 143,1 MiB, prin lanțul real:

| | octeți |
|---|---:|
| un sistem always-upload ar fi trimis | 150.070.385 |
| a primit efectiv | 264.593 |
| conținut de fișier | 0 |

**De ~567 de ori mai puțin.**

Numitorul nu e estimat: `file_size` e obligatoriu prin contract la orice
eveniment cu amprentă validă, cu motivul scris acolo — nu se poate reconstrui
retroactiv dacă fișierul s-a schimbat între timp.

Metrica ține separat **conținutul divulgat** de **costul metadatelor**. Zero
conținut nu înseamnă cost zero: canalul de evenimente circulă la fiecare fișier
atins, nu doar la cele escaladate, iar o metrică ce ar raporta doar conținutul ar
fi adevărată și înșelătoare în același timp.

Raportează explicit și ce **nu poate** număra: fișierele fără amprentă reușită
n-au dimensiune, deci numitorul e o subestimare. Statusurile rămân separate,
pentru că `unstable` e cost impus de fișier, iar `skipped_capacity` și
`skipped_shutdown` sunt cost impus de agent.

---

## Rulare și operare

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
EDR_ENROLLMENT_SECRET=alege-un-secret .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Fără variabila de mediu, serverul generează singur un secret și îl scrie în
`enrollment_secret.txt`, logând **calea**, niciodată valoarea. Nu există mod
„fără secret": un server care ar accepta înrolări neautentificate când
configurarea lipsește ar transforma o omisiune de operator într-o gaură tăcută.

Revocarea unei chei se face direct pe server:

```python
from app.services import auth_service
auth_service.revoke_agent_key("endpoint-01")
auth_service.list_key_records()   # amprente, niciodată chei
```

Are efect după repornirea serverului — cheile trăiesc în memoria procesului. E o
limitare cunoscută, urmărită ca issue.

Testele — **116**:

```bash
.venv/bin/python -m pytest app/tests -q
```

Verificările cross-repo cer clona `edr-agent` alături. Absența ei e skip local și
eșec sub CI; `EDR_REQUIRE_PEER_REPO` forțează oricare comportament.

---

## Cum a fost construit

**Contractul de fir e un artefact partajat, verificat automat.** `edr-agent` nu
poate importa modulele de aici — sunt repo-uri separate — deci își ținea propria
copie a numelor de câmpuri, actualizată din memoria unui om. Un câmp redenumit pe
o singură parte nu producea nicio eroare: producea **date lipsă**, descoperite
luni mai târziu.

`contracts/wire-contract.json` e comis identic în ambele repo-uri. Testele
confruntă schemele Pydantic cu el, *și* cele două exemplare între ele. La fel
pentru `contracts/AUTH.md`, unde o divergență ar produce un `401` permanent care
arată exact ca o cheie greșită.

**Un câmp necunoscut se aude, dar nu respinge.** Pydantic aruncă implicit cheile
nedeclarate: agentul primea `200 OK`, iar câmpul rămânea `None`. `WireModel`
loghează acum cheia, cu numele ei.

Deliberat *nu* `extra="forbid"`, deși ar face greșeala imposibil de ratat: un
`422` ar face agentul să trateze evenimentul ca poison message și să-l șteargă.
Adică exact greșeala pe care „forbid" o face vizibilă ar opri monitorizarea. Un
câmp necompletat e recuperabil; un eveniment șters, nu.

**Testele apără invariante, nu linii.** Un test verifică faptul că înregistrarea
nu adoptă incarnarea; altul, că modelul de eveniment nu poate purta conținut —
prin **forma numelui de câmp**, nu printr-o listă fixă, deci acoperă și câmpuri
pe care nimeni nu le-a inventat încă.

**Fiecare problemă devine întâi un issue**, care numește lanțul de eșec, nu
simptomul. Urma scrisă a problemelor găsite face parte din valoarea lucrării.

**Verificare manuală end-to-end**, cu agentul pe altă mașină: chei greșite,
identități împrumutate, revocări, restarturi de server cu registru volatil.

35 de commituri, 7 issue-uri închise.

---

## Contribuții proprii

Partea de server a lucrării:

1. **Metrica de divulgare ca proprietate verificabilă**, nu ca afirmație.
   Numitorul e impus prin contract și protejat de validator, tocmai pentru că nu
   se poate reconstrui retroactiv. Un EDR care spune că trimite puțin face o
   promisiune; unul care măsoară și publică raportul face o afirmație care poate
   fi infirmată.

2. **Separarea a trei semnale de continuitate** care erau confundate într-un
   singur contor, cu argumentul cantitativ pentru care durata nu poate fi
   derivată din secvență.

3. **Ferestre ratate derivate din ceasul propriu al serverului**, fără câmp nou
   pe fir și fără încredere în ceasul unui endpoint posibil compromis.

4. **Depozit de credențiale hash-uit și persistat separat de registrul volatil**,
   astfel încât calea de recuperare a parcului să supraviețuiască repornirii
   serverului.

5. **Coduri de răspuns alese după ce face agentul cu ele**, nu după convenția
   HTTP — cu ordinea verificărilor aleasă ca să nu ofere enumerare.

6. **Contracte cross-repo verificate automat**, cu politică explicită pentru
   absența repo-ului pereche: skip local, eșec sub CI. Un skip tăcut pe o mașină
   de integrare face exact cel mai puternic test din suită să tacă.

---

## Future work

**Mașina de stări per fișier.** Determinarea autoritară a noutății: prima
apariție a acestui hash la această cale. E deja declarată în contract ca
responsabilitate a serverului, dar neimplementată. Fără ea nu există prevalență,
deci nici decizie de escaladare — iar `collect_file_path` din directiva de
heartbeat rămâne un câmp nefolosit.

**Registrul de divulgare.** Contabilizarea fiecărui octet care a părăsit un
endpoint, ca garanția „niciun conținut pe canalul de evenimente" să fie
verificată semantic, nu doar prin forma numelor de câmpuri.

**Autentificarea rutelor de citire**, împreună cu un secret propriu pentru
analist și drepturi distincte de cele ale agenților.

**Revocare fără repornire.** Astăzi o revocare rescrie fișierul, dar procesul
care rulează ține cheile în memorie și nu îl recitește.

**Persistență reală.** `agents_store` și `events_store` sunt structuri în
memorie. Depozitul de chei e deja persistat, pentru că altfel repornirea ar fi
blocat parcul; restul nu e, iar metrica de divulgare se calculează deci doar
peste evenimentele rulării curente.

**TLS.** Terminarea TLS și emiterea certificatelor. Astăzi cheia de API circulă
în clar, iar autentificarea apără împotriva unui client fără secret, nu împotriva
unui ascultător pe traseu.

Problemele deschise: [issues](https://github.com/ZiGabiZi/edr-server/issues).
