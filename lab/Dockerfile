FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    WITNESS=VBOX-OVF-NAT-TFTP-PREFIX-WITNESS

WORKDIR /lab

RUN mkdir -p /oracle /work/tftp \
    && printf '%s' "${WITNESS}" > "/oracle/${WITNESS}" \
    && printf '%s' 'pxe-under-prefix' > /work/tftp/boot.pxe \
    && chmod 0755 /oracle /work /work/tftp \
    && chmod 0644 "/oracle/${WITNESS}" /work/tftp/boot.pxe

COPY poc.py tftp_rrq.py /lab/

RUN chmod 0755 /lab/poc.py /lab/tftp_rrq.py

CMD ["sleep", "infinity"]
