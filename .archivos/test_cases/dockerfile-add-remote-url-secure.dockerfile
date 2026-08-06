FROM ubuntu:22.04
# Prefer COPY or curl/wget with hash verification
# RUN curl -sSL https://example.com/script.sh -o /tmp/script.sh \
#     && echo "sha256_hash /tmp/script.sh" | sha256sum -c -