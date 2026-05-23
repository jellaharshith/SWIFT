"""Per-specialist prompt + tool wirings (currently consolidated in
:mod:`agent.langgraph_layer.specialists` for brevity).

Re-exported here so importers can use either path:

    from agent.langgraph_layer.agents import SPECIALISTS, Specialist
"""
from agent.langgraph_layer.specialists import SPECIALISTS, Specialist

__all__ = ["SPECIALISTS", "Specialist"]
