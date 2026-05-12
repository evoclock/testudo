# Testudo runtime image.
#
# Builds the testudo:0.1 image used by the host-side runtime as the default
# isolation target. The image carries the testudo Python package and runs the
# in-container orchestrator on the bind-mounted /workflow.json by default.
#
# Build:
#   docker build -t testudo:0.1 .
#
# Run (typically via the testudo runtime, not by hand):
#   docker run --rm \
#     -v $(pwd)/examples/workflow-meeting-debrief.json:/workflow.json:ro \
#     -v $(pwd)/runs:/runs \
#     testudo:0.1

FROM python:3.12-slim

LABEL org.opencontainers.image.title="testudo"
LABEL org.opencontainers.image.description="Dockerised agent runtime with declarative permissioning, audit logging, and an embedded lightweight orchestrator."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/evoclock/testudo"
LABEL org.opencontainers.image.vendor="Julen Gamboa"

# Non-root user inside the container; the orchestrator never needs root.
RUN useradd --create-home --uid 1000 testudo

WORKDIR /testudo

# Install the package. Copying only the bits needed for installation keeps
# the image cache friendly when source under src/testudo/ changes.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

USER testudo
WORKDIR /runs

# ENTRYPOINT runs the in-container orchestrator. CMD is the default workflow
# path; callers (the host-side runtime) override this with the bind-mounted
# /workflow.json target.
ENTRYPOINT ["python", "-m", "testudo.orchestrator"]
CMD ["/workflow.json"]
