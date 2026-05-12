"""Testudo prompts package.

Purpose: prompt assembly. Loads XML-format templates from a workflow's prompt
library and performs ``{{placeholder}}`` substitution to produce the final
prompt text passed to the model layer. Templates are plain text in version
control; edits do not require redeployment.

Inputs: a template name (looked up via ``PromptLibrary``) or a path to a
template file; a dict of substitution variables.

Outputs: the assembled prompt string ready for the model client.

Assumptions: templates use the convention
``<context>...</context><data>...</data><task>...</task><output_format>...</output_format>``
with ``{{name}}`` placeholders for runtime substitution. Conditional logic
stays in natural language inside ``<task>``; the assembler does no branching.
"""

from testudo.prompts.library import PromptLibrary
from testudo.prompts.template import PromptTemplate, assemble_prompt, load_template

__all__ = [
    "PromptLibrary",
    "PromptTemplate",
    "assemble_prompt",
    "load_template",
]
