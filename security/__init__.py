"""Security Information Management (SIM) layer for the SQLi lab.

Three small pieces, each doing one job:

* ``events``    - write every login attempt as one structured JSON line.
* ``detector``  - look at the submitted text and name any SQLi warning signs.
* ``alerts``    - read the event log and raise alerts when events add up
                  to a pattern (correlation).
"""
