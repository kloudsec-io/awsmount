"""Interactive shell and one-shot commands over the VFS (ARCHITECTURE: Shell).

:mod:`awsmount.adapters.shell.commands` has no prompt_toolkit
dependency; the REPL and the completer (which need prompt_toolkit) live
in :mod:`~awsmount.adapters.shell.repl` and
:mod:`~awsmount.adapters.shell.completer` and are imported on demand.
"""

from __future__ import annotations

from awsmount.adapters.shell.commands import COMMANDS, Command, Shell

__all__ = ["COMMANDS", "Command", "Shell"]
