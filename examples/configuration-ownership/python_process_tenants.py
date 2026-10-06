import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import redact_secret

TEXT = "email: owner.synthetic@mail-synthetic.org\nclient_ip = 192.168.1.7\n"
TENANTS = {
    "pii-off": (),
    "pii-global": ("pii:global",),
    "network-address-only": ("pii:family:global:network-address",),
}


def configure(pii):
    # Runs once in the tenant's own process, the only place its selection lives.
    redact_secret.initialize(pii=pii)


def scan_types():
    return sorted(finding.type for finding in redact_secret.scan(TEXT))


def main():
    # One single-process pool per tenant. "spawn" gives every worker a fresh
    # interpreter, so no selection is inherited from this process.
    context = multiprocessing.get_context("spawn")
    for tenant, pii in TENANTS.items():
        with ProcessPoolExecutor(1, mp_context=context, initializer=configure, initargs=(pii,)) as pool:
            print(tenant, pool.submit(scan_types).result())

    # Inside one process the first selection wins and a different one conflicts.
    redact_secret.initialize(pii=("pii:global",))
    try:
        redact_secret.initialize(pii=("pii:family:global:network-address",))
    except redact_secret.PiiActivationConflictError as error:
        print(error.code)


if __name__ == "__main__":
    main()
