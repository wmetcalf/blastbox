# rea-model-gw: the model gateway (blastbox.engines.rea.model_gateway), the only holder of
# hosted-model credentials. Build from the REPO ROOT:
#   docker build -f deploy/rea/model-gw/Dockerfile -t blastbox-rea-model-gw .
# Only grant.py and model_gateway.py are copied (plus empty package __init__ files): the agent
# and Ghidra stack are never in this image, and the `blastbox` package __init__ is replaced by an
# empty one so importing the gateway pulls in nothing else.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY deploy/rea/model-gw/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps --only-binary :all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

RUN mkdir -p /app/blastbox/engines/rea \
    && touch /app/blastbox/__init__.py /app/blastbox/engines/__init__.py /app/blastbox/engines/rea/__init__.py
COPY src/blastbox/engines/rea/grant.py src/blastbox/engines/rea/model_gateway.py /app/blastbox/engines/rea/

ENV PYTHONPATH=/app
USER 1000:1000
EXPOSE 8080
CMD ["python", "-m", "blastbox.engines.rea.model_gateway"]
