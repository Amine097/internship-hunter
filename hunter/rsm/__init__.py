"""Resource Session Manager (RSM): the minimal host-side helper that frees RAM for a research
session by stopping an administrator-approved set of Docker containers and restoring them.

SECURITY: this package runs on the HOST with access to the rootful Docker daemon, which is
root-equivalent. It therefore:
  * imports nothing outside the standard library,
  * exposes exactly five operations and accepts no container names, commands or paths,
  * only ever acts on names listed in a root-owned policy file,
  * is never imported by the application containers (they speak to it over a Unix socket).
"""
OPERATIONS = ("prepare", "stop_approved", "restore", "status", "emergency_restore")
