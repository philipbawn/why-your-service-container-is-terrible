# A Ghost of an IoC Container

> **A stochastic risk assessment of a service container that has mistaken “still compiles” for “still safe to trust.”**

Co-written with GPT 5.6-sol xhigh and Claude-Fable-5 xhigh

## Verdict

That container is dangerous to adopt as a general-purpose .NET 9/10 service provider in 2026.

“Dangerous” does **not** mean “proven remote-code-execution exploit.” It means their implementation silently violates framework contracts at boundaries commonly trusted with tenant routing, service selection, object ownership, cleanup, scope isolation, and application shutdown. Those failures are reproducible. Several produce the worst possible operational outcome: the application reports success while doing the wrong thing.

The short version:

| Area | Demonstrated behavior | Risk |
|---|---|---|
| Keyed DI | Erases key type through `ToString()`, collides distinct keys, passes counterfeit strings to factories and constructors, lets a keyed-only registration satisfy an unkeyed lookup, dereferences null keys, and misses .NET 10 `AnyKey` behavior | Wrong implementation selection; startup failure; potential tenant/policy boundary confusion |
| Disposal | Disposes externally owned objects, can dispose one object twice, swallows sync and async cleanup failures, blocks sync-over-async, and leaks objects across shutdown races | Data loss, resource leakage, corrupt native state, false-positive shutdown success |
| Validation | Creates a scope for “full” validation and then resolves non-singletons from the root; host integration exposes no `ServiceProviderOptions` equivalent | Captive dependencies and promoted lifetimes can escape the safety net |
| Caching | Uses a 32-bit hash as the sole scoped/singleton cache key; collision mitigation is optional | Unrelated services can alias in a scope |
| Live mutation | One overload forbids nested mutation while another permits it; the guard contains a duplicated predicate | Runtime graph changes with inconsistent safety rules |
| Assurance | A disposal compliance test is disabled with `// Don't care`; a concurrency integration test self-starves; analyzers identify tests that are not tests | Green checks overstate confidence |
| Repository security | Restore reports critical, high, and moderate advisories in test/sample/build dependencies; workflows use old, mutable action tags | CI and maintainer exposure, distinct from the shipped core package |

That is not a container. It is a haunted coat-check using `GetHashCode()` for the tickets, `ToString()` for identity documents, and an exception shredder behind the counter.

---

## 1. Keyed services, now with the key filed off

The .NET contract accepts an object key. Microsoft is explicit: **a key is not limited to `string`; it can be any object whose type implements equality correctly** ([Microsoft Learn: keyed services](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/overview#keyed-services)). Their implementation accepts the same API shape and then quietly converts the key to text.

### Source receipts

- `Instance.cs:141–173` converts `ServiceDescriptor.ServiceKey` with `?.ToString()`, stores the result as the registration name, passes that string to keyed factories, and discards the original key object.
- `ServiceFamily.cs:175–188` renames every member of a same-name group during family construction, so two keys with identical text both lose their original identity.
- `ServiceFamily.cs:29–46` chooses the last registration as the family default without excluding keyed registrations; `ServiceGraph.cs:368–405` uses that default for ordinary unkeyed resolution.
- `Scope.cs:375–384` throws when the capability API receives a non-string key.
- `Scope.cs:489–497` nevertheless accepts any object in the resolution API and immediately calls `serviceKey.ToString()` without a null check.
- `ServiceGraph.cs:230–233` calls `ToString()` on the nullable key carried by `[FromKeyedServices]`.
- `ConstructorInstance.cs:414–418` injects the registration’s string `Name` for `[ServiceKey]`, regardless of the original key type.

That is not keyed DI. That is stringly typed service location wearing an object-shaped fake moustache.

### Reproduced behaviors

The private characterization harness observed all of the following on .NET 10:

1. Integer key `1` and string key `"1"` collapse to the same name. Name de-duplication renames both registrations, after which lookups by either original key fail.
2. An integer-keyed factory receives string `"42"`, not integer `42`.
3. A constructor parameter marked `[ServiceKey]` receives string `"42"`, not integer `42`.
4. The capability query throws for an integer key while resolution of that same key succeeds in the single-registration case.
5. A null keyed lookup throws `NullReferenceException`.
6. Inherited keyed resolution with the attribute’s null key crashes during container construction.
7. With only a keyed registration present, an ordinary unkeyed lookup returns that keyed service. Microsoft’s provider returns no unkeyed service.
8. A singular lookup with `KeyedService.AnyKey` returns no service instead of throwing the .NET 10-mandated `InvalidOperationException`. Microsoft documents that rule explicitly ([Microsoft Learn: `AnyKey`](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/overview#keyedserviceanykey-property)).

### Why that is dangerous

Keyed DI is often used to select a tenant-specific backend, authorization policy, serializer, payment rail, cache, or external client. Type-erasing keys can make distinct security domains indistinguishable. The probe does not claim that every application uses keys as a security boundary; it proves their container cannot preserve that boundary when an application does.

The public interface promises object-key semantics. The implementation delivers lossy string aliases. That is a contract violation with security consequences, not a missing convenience feature.

---

## 2. Disposal by denial, duplication, and disappearance

Microsoft’s ownership rule is unambiguous: when an application registers an already-created instance, the framework container does **not** dispose it; the developer owns it ([Microsoft Learn: services not created by the container](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/guidelines#services-not-created-by-the-service-container)). Their implementation chooses the opposite behavior.

### Source receipts

- `ObjectInstance.cs:9–24` wraps a user-supplied object and disposes it.
- `ServiceGraph.cs:76–116` walks every object registration at shutdown. It does not de-duplicate the underlying object and suppresses both synchronous and asynchronous disposal exceptions.
- `Scope.cs:73–148` snapshots a `ConcurrentBag`, clears it, and suppresses async disposal exceptions with the comment `// Yup, don't let that go out`.
- Synchronous disposal failures route through a shared `SafeDispose` extension supplied by an upstream utility library; its implementation is an empty `catch` annotated `// That's right, swallow that exception`.
- `AsyncDisposableWrapper.cs:20–23` converts synchronous disposal into `.DisposeAsync().GetAwaiter().GetResult()`.
- `Scope.cs:461–472` publicly accepts more disposables without checking whether the scope is already dead.
- `Container.cs:47–83` uses unsynchronized Boolean flags for the disposing state.

Microsoft’s built-in provider takes a deliberately safer position: synchronous `Dispose()` throws when it encounters an async-only service, telling the caller to use `DisposeAsync()` instead ([Microsoft Learn: `ServiceProvider.Dispose`](https://learn.microsoft.com/dotnet/api/microsoft.extensions.dependencyinjection.serviceprovider.dispose?view=net-10.0)). Here, sync-over-async is performed inside the container, where a captured synchronization context can turn shutdown into a deadlock séance.

### Reproduced behaviors

1. A user-created singleton is disposed by the container.
2. The same user-created object registered under two service interfaces is disposed twice.
3. An `IDisposable` that throws is treated as successfully disposed; the exception never reaches the caller.
4. An `IAsyncDisposable` that throws is also treated as successfully disposed.
5. Synchronous shutdown blocks on an async-only object and reports success.
6. A disposable added after shutdown is accepted, never disposed, and cannot be recovered by calling shutdown again.
7. A transient whose constructor begins before shutdown and completes afterward is added too late for the disposal snapshot. It leaks permanently; the container’s “already disposing” flag prevents a second cleanup pass.

Microsoft says the container is responsible for disposing what it creates according to lifetime, and warns that root-resolved disposable transients are retained until root shutdown ([Microsoft Learn: disposal and transient capture](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/guidelines#disposal-of-services)). Their implementation adds new failure modes around that already-sensitive contract.

### Operational consequence

Cleanup is where database buffers flush, telemetry exporters drain, files close, leases release, native handles unwind, and transactional resources report failure. Swallowing those exceptions converts “shutdown failed” into “everything is fine.” Double-disposal is equally unsafe for types whose second call is not idempotent. Leaking across a shutdown race makes correctness depend on a timing window the caller cannot see.

The exception policy here is not resilience. It is witness protection.

---

## 3. Scope validation performed with a ceremonial scope

Microsoft’s scope validation checks that scoped services are neither resolved from the root nor injected into singletons. A scoped service created at the root is effectively promoted to singleton ([Microsoft Learn: scope validation](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/overview#scope-validation)).

### Source receipts

- `Container.cs:236–275` creates a temporary scope for non-singleton validation.
- `Container.cs:243` then resolves every non-singleton with `instance.Instance.Resolve(this)`—the root container—not the `scope` it just created.
- `*ServiceProviderFactory.cs:6–30` constructs the provider directly and accepts no `ServiceProviderOptions` (the identifying filename prefix is omitted here).
- `HostBuilderExtensions.cs:34–50` and `60–83` replace the host provider without forwarding a `ValidateScopes` or `ValidateOnBuild` equivalent.

The temporary scope is architectural stage dressing. The actual resolution happens through the root.

### Reproduced behavior

A transient disposable created by “full” validation has a disposal count of zero after the temporary scope closes and one only after the root container closes. The validation routine therefore demonstrates the very root-lifetime promotion that framework scope validation exists to prevent.

This matters because Development-mode host defaults cannot protect an application when a replacement provider does not implement equivalent validation. A method named “assert configuration is valid” is especially hazardous when its execution model contaminates the root it is supposedly checking.

---

## 4. The cache key is a 32-bit hope

### Source receipts

- `Instance.cs:393–401` reduces service type plus name to one signed 32-bit hash.
- `Instance.cs:373–381`, `ScopedResolver.cs:12–33`, `SingletonResolver.cs:21–54`, and `GeneratedInstance.cs:102–153` use that integer as the cache lookup key. The original type and name are not checked on retrieval.
- `ServiceRegistry.HashCollisionMitigation.cs:23–42` exposes collision mitigation as an opt-in operation.
- The mitigation renames unnamed registrations to obtain another hash and throws for multiple explicitly named registrations (`ServiceRegistry.HashCollisionMitigation.cs:61–74`).

The private harness assigned the same public `Hash` value to two unrelated scoped registrations. Resolving the first poisoned the cache slot; resolving the second retrieved the first object and failed the generic cast.

An ordinary accidental collision is probabilistic, not guaranteed. A deliberate collision is trivial for code that can influence registrations because the cache hash is publicly settable (`Instance.cs:50` declares `public int Hash { get; set; }`). This is primarily an in-process plugin/configuration threat, not a claim that an unauthenticated remote caller can rewrite registrations.

Correct cache identity is a composite key with equality verification. Renaming services until the roulette wheel lands elsewhere is not collision handling; it is bargaining with arithmetic.

---

## 5. Runtime mutation: forbidden, permitted, and copy-pasted

### Source receipts

- `Container.cs:104–108` and `124–127` label live configuration “NOT RECOMMENDED.”
- `Container.cs:111–119` contains the exact same family-policy predicate and exception twice.
- `Container.cs:128–139` prevents the callback overload from mutating a nested container.
- The direct collection overload at `Container.cs:109–122` contains no root check and mutates the shared service graph anyway.
- `ServiceGraph.cs:548–578` appends families, invalidates resolver entries, resets planning globally, and rebuilds generated-resolution metadata while the provider is live.

The harness confirmed that a nested container can mutate the shared graph through the direct overload, while the callback overload throws for the same operation.

Microsoft says resolution from a built provider or scope is thread-safe ([Microsoft Learn: thread safety](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/guidelines#thread-safety)). A replacement provider that advertises live graph mutation owes users a much stronger synchronization and state-transition story than “one overload remembered the guard.”

---

## 6. The tests are green where they remembered to be tests

Credit where it is due: this snapshot has substantial test coverage, and the executed suites were not ignored.

| Run | Result |
|---|---:|
| Core suite, .NET 10 | 714 passed |
| ASP.NET Core suite, .NET 10 | 23 passed |
| Minimal API suite, .NET 10 | 2 passed |
| Private differential characterization harness | 24 observed (18 subject behaviors + 6 Microsoft-provider controls), 0 mismatches |

An independent rerun on 2026-07-20 reproduced the core-suite and minimal-API results exactly (714 and 2 passed, 0 failed) and re-emitted every analyzer-warning class cited below; the ASP.NET Core suite’s 23 executed cases match its 23 test attributes.

That counterevidence makes the conclusion stronger: broad feature tests pass while dangerous boundary behavior remains reproducible.

### Assurance receipts

- `AspNetCoreCompliance.cs:83–108` contains `DisposesInReverseOrderOfCreation`, but its `[Fact]` is commented out beneath `// Don't care`. The compiler correctly warns that the public method on a test class is not a test.
- `IntegrationTests.cs:60–71` declares a concurrency test as `async void`, preventing normal task-based test lifecycle tracking.
- `SuccessHealthCheck.cs:90–96` busy-spins for two seconds inside a test critical section.
- `IHealthCheckExtensions.cs:19–27` registers twenty custom checks, and `32–59` makes each check factory enter that critical section. `IntegrationTests.cs:73–100` then requests the health endpoint twenty times sequentially.
- On the recorded run, one unrelated test passed and the health test exceeded a 60-second inactivity timeout. The managed hang dump showed numerous worker threads inside the busy loop. This is test-induced thread-pool starvation, **not** evidence of a container deadlock.
- The build emitted analyzer warnings for blocking task operations in multithreading and disposal tests, duplicate theory data, unused theory parameters, and public methods that xUnit does not execute.

A disabled compliance assertion preceded by “Don’t care” is refreshingly honest. It is also not compliance.

---

## 7. Supply-chain reality: clean passenger cabin, burning maintenance hangar

The distinction matters:

- A direct `dotnet list ... package --vulnerable --include-transitive` audit of the **shipped core project** reported no known vulnerable packages from the configured sources.
- Restoring/building the **whole repository** emitted advisories in test, sample, and build projects. These do not automatically flow to consumers of the core package, but they do execute in CI and on maintainer machines.

Observed repository warnings included:

- **Critical:** `System.Drawing.Common` 4.7.0/5.0.0 ([GHSA-rxg9-xrhp-64gj](https://github.com/advisories/GHSA-rxg9-xrhp-64gj)).
- **High:** `System.Data.SqlClient` 4.8.1/4.8.2/4.8.5 and `Microsoft.Data.SqlClient` 2.0.1 ([GHSA-98g6-xh36-x2p7](https://github.com/advisories/GHSA-98g6-xh36-x2p7)).
- **High:** `AutoMapper` 9.0.0 ([GHSA-rvv3-g6hj-g44x](https://github.com/advisories/GHSA-rvv3-g6hj-g44x)).
- **High:** `SQLitePCLRaw.lib.e_sqlite3` 2.0.4 ([GHSA-2m69-gcr7-jv3q](https://github.com/advisories/GHSA-2m69-gcr7-jv3q)).
- **High, build tooling:** `Newtonsoft.Json` 12.0.3 ([GHSA-5crp-9r3c-p9vr](https://github.com/advisories/GHSA-5crp-9r3c-p9vr)) and `Npgsql` 4.1.3.1 ([GHSA-x9vc-6hfv-hg8c](https://github.com/advisories/GHSA-x9vc-6hfv-hg8c)).
- **Moderate:** the restored graphs also report `System.Data.SqlClient`/`Microsoft.Data.SqlClient` ([GHSA-8g2p-5pqh-5jmc](https://github.com/advisories/GHSA-8g2p-5pqh-5jmc)), `IdentityServer4` 4.1.2 ([GHSA-55p7-v223-x366](https://github.com/advisories/GHSA-55p7-v223-x366), [GHSA-ff4q-64jc-gx98](https://github.com/advisories/GHSA-ff4q-64jc-gx98)), `KubernetesClient` 3.0.12 ([GHSA-w7r3-mgwf-4mqq](https://github.com/advisories/GHSA-w7r3-mgwf-4mqq)), `Microsoft.Rest.ClientRuntime` 2.3.10 ([GHSA-whph-446h-6m9v](https://github.com/advisories/GHSA-whph-446h-6m9v)), `Swashbuckle.AspNetCore.SwaggerUI` 5.6.3 ([GHSA-qrmm-w75w-3wpx](https://github.com/advisories/GHSA-qrmm-w75w-3wpx)), `System.DirectoryServices.Protocols` 5.0.0 ([GHSA-9cxh-gqpx-qc5m](https://github.com/advisories/GHSA-9cxh-gqpx-qc5m)), and `System.Security.Cryptography.Xml` 5.0.0 ([GHSA-vh55-786g-wjwj](https://github.com/advisories/GHSA-vh55-786g-wjwj)).

Workflow hygiene adds avoidable exposure:

- CI, documentation, and publish workflows use mutable major-version tags such as `actions/checkout@v2`, `actions/setup-dotnet@v1`/`@v3`/`@v4`, and `actions/setup-node@v1`, rather than immutable commit SHAs.
- The documentation publisher constructs an authenticated Git URL containing the workflow token (`build.cs:151–167`). That credential is passed to `git clone` and retained in the clone’s remote configuration for the job lifetime.
- Package publishing pushes directly after build and pack with no visible provenance/attestation stage.

None of this proves the published runtime package is presently compromised. It proves the development and release environment has a larger, older attack surface than its core dependency audit suggests.

---

## 8. Why “dangerous in 2026” is the defensible conclusion

A replacement container occupies a privileged position. Every request may trust it to:

1. select the correct implementation;
2. preserve scope and tenant boundaries;
3. construct each object once when promised;
4. return the object that was registered;
5. dispose exactly the objects it owns, exactly once;
6. surface cleanup failure;
7. remain coherent under concurrency; and
8. match the host framework’s compatibility contract.

Their implementation demonstrably breaks items 1, 2, 4, 5, 6, 7, and 8 under compact, deterministic probes.

Microsoft recommends the built-in provider unless an application needs a specific unsupported feature, and lists property injection, child containers, custom lifetimes, lazy factories, and convention registration as examples ([Microsoft Learn: default container replacement](https://learn.microsoft.com/dotnet/core/extensions/dependency-injection/guidelines#default-service-container-replacement)). Extra features can justify a replacement. They do not excuse weaker object identity, ownership, or shutdown semantics.

The danger is not that every application will trigger every defect. The danger is that application code cannot locally defend against a provider that silently changes key identity, owns objects it did not create, suppresses cleanup failure, validates through the wrong scope, or aliases cache entries without verifying identity.

This ghost does not merely rattle chains. It occasionally hands you somebody else’s service, burns the disposal receipt, and tells the host everything went beautifully.

---

## 9. Minimum exit criteria before production trust

1. Preserve keyed-service keys as objects end-to-end, including equality semantics, keyed-versus-unkeyed separation, null/inherited lookup modes, factory arguments, `[ServiceKey]`, `AnyKey`, and keyed enumerables.
2. Add compatibility tests against current Microsoft DI specification behavior for .NET 9 and .NET 10.
3. Track ownership separately from lifetime; never dispose caller-owned instances by default.
4. De-duplicate disposal by object identity and define reverse-creation ordering.
5. Propagate cleanup exceptions, or aggregate them without reporting false success.
6. Remove internal sync-over-async; require async shutdown for async-only services.
7. Make resolve-versus-dispose transitions atomic and reject additions after disposal.
8. Implement host scope/build validation options and resolve validation targets through the validation scope.
9. Replace hash-only cache identity with a collision-safe composite key and equality check.
10. Remove or freeze live graph mutation; at minimum, make both overloads enforce identical root and concurrency rules.
11. Re-enable disposal compliance tests, replace `async void`, and replace busy loops with deterministic synchronization.
12. Update vulnerable development dependencies, pin actions by commit SHA, and add package provenance/attestation.

Until then, production use is an acceptance of undocumented behavior at exactly the layer intended to make object behavior predictable.

---

## Methodology and limits

- Assessment date: **2026-07-20**.
- Findings were derived from the checked-out source, its project/workflow files, executed tests, NuGet audit output, a managed hang dump, and a private executable characterization harness.
- Source citations use filename and line range relative to the inspected source tree; identifying branding and paths are intentionally omitted.
- Every source receipt, executed-suite count, Microsoft Learn passage, and GitHub advisory cited above was independently re-verified against the snapshot on 2026-07-20.
- The harness is being retained privately under proprietary copyright and is not embedded in this document.
- Probe findings describe this exact snapshot and runtime. They should be rerun after any change.
- Advisory status is time-sensitive. The core project and repository-wide dependency graphs are reported separately.
- No claim of malicious intent, active exploitation, or universal application impact is made.

**Final recommendation:** do not adopt A Ghost of an IoC Container for new production systems. Existing users should prioritize keyed-service, ownership/disposal, scope-validation, and shutdown-race audits before the next deployment.
