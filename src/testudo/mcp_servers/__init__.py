"""Testudo MCP servers package.

Three in-house MCP servers ship with v0.1.5:

- :mod:`testudo.mcp_servers.file_extractor` -- read-only document
  extraction. Parses PDF, DOCX, HTML, plain text, and images (OCR if
  ``pytesseract`` is installed). Strips metadata, HTML comments, hidden
  unicode, and external links before returning the cleaned text. This
  server has zero write capability.
- :mod:`testudo.mcp_servers.llm_response_capturer` -- read-only model
  response capture. Receives LLM tool-call output, runs the output-side
  sanitiser, and emits a structured result the host can then hand to the
  write-side server. Has no filesystem-write capability.
- :mod:`testudo.mcp_servers.file_writer` -- write-side file operations.
  Modelled on hillstar's ``file_operations_mcp_server.py``; the only
  server with write permission. Accepts only payloads that carry a valid
  sanitisation receipt from the capturer (HMAC-signed; rotates per run).

All three speak JSON-RPC 2.0 over STDIO (the local-only transport per MCP
presentation v4 slide 11). HTTP/SSE is intentionally not exposed in v0.1;
remote servers are out of scope until network-egress allow-listing is
finalised.
"""

from testudo.mcp_servers.base import BaseMCPServer

__all__ = ["BaseMCPServer"]
