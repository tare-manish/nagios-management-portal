"""Privileged helpers for Nagios Management Portal.

Standard library only. Installed root-owned under
/opt/nagios-management/privileged and executed through a restricted
sudoers rule. Nothing here accepts a path or command from the caller:
callers pass only numeric IDs / backup names that are validated against
strict patterns and resolved inside fixed directories.
"""
