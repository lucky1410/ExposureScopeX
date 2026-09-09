# Integration services package.
#
# Importing each provider module here causes their @register decorators to run,
# populating REGISTRY so get_service() can instantiate any provider by slug.

from app.services.integrations.base import (  # noqa: F401
    IntegrationService,
    REGISTRY,
    register,
    get_service,
)

# Provider modules — import order does not matter; all call @register on load.
from app.services.integrations import slack          # noqa: F401
from app.services.integrations import teams         # noqa: F401
from app.services.integrations import pagerduty     # noqa: F401
from app.services.integrations import splunk        # noqa: F401
from app.services.integrations import elastic       # noqa: F401
from app.services.integrations import jira_cloud    # noqa: F401
from app.services.integrations import github_sarif  # noqa: F401
from app.services.integrations import greynoise     # noqa: F401
