"""
SecureStorageInspector — Rule Loader

Auto-imports all rule modules in this package and aggregates their
rules into a single list via ``get_all_rules()``.

To add new rules, create a ``.py`` file in this directory that exports
a ``get_rules() -> list[SecurityRule]`` function. It will be picked
up automatically.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from backend.engine.rules_engine import SecurityRule

logger = logging.getLogger(__name__)


def get_all_rules() -> List[SecurityRule]:
    """
    Discover and load all rules from sub-modules in this package.

    Each sub-module must export a ``get_rules()`` function that returns
    a ``list[SecurityRule]``.

    Returns:
        Combined list of all SecurityRule objects.
    """
    all_rules: List[SecurityRule] = []

    # Iterate over all modules in this package
    package_path = __path__  # type: ignore[name-defined]
    for finder, module_name, is_pkg in pkgutil.iter_modules(package_path):
        if module_name.startswith("_"):
            continue  # skip __init__ and private modules

        try:
            module = importlib.import_module(f".{module_name}", package=__name__)
            if hasattr(module, "get_rules"):
                rules = module.get_rules()
                all_rules.extend(rules)
                logger.debug(
                    "Loaded %d rules from %s", len(rules), module_name
                )
            else:
                logger.warning(
                    "Rule module '%s' has no get_rules() function — skipping.",
                    module_name,
                )
        except Exception as exc:
            logger.error(
                "Failed to load rule module '%s': %s", module_name, exc
            )

    return all_rules
