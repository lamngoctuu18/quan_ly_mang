"""Remote agent client and task execution providers."""

from lan_manager.infrastructure.remote.agent_client import (
    AgentRequestVerifier,
    AuthenticatedAgentClient,
)
from lan_manager.infrastructure.remote.task_executor import (
    CompositeTaskExecutor,
    RemoteExecutionProvider,
    TaskExecutionOutput,
)

__all__ = [
    "AgentRequestVerifier",
    "AuthenticatedAgentClient",
    "CompositeTaskExecutor",
    "RemoteExecutionProvider",
    "TaskExecutionOutput",
]
