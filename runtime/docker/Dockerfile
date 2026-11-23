FROM mcr.microsoft.com/playwright/python@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031
LABEL siteproof.task="M2-RUNTIME-VALIDATION-01"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_CONFIG_FILE=/dev/null
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 libnss3-tools
RUN python -m pip download --index-url https://pypi.org/simple --only-binary=:all: --dest /opt/siteproof-distributions playwright==1.64.1 && sha256sum /opt/siteproof-distributions/* > /opt/siteproof-distributions/SHA256SUMS && python -m pip install --no-index --find-links=/opt/siteproof-distributions playwright==1.64.1
WORKDIR /opt/siteproof
COPY src ./src
COPY web ./web
COPY runtime/docker ./runtime/docker
COPY tests/runtime ./tests/runtime
COPY tests/__init__.py ./tests/__init__.py
COPY tests/isolation/transport_fixtures.py ./tests/isolation/transport_fixtures.py
USER 1000:1000
CMD ["python", "-c", "import time; time.sleep(86400)"]
