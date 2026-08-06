FROM ubuntu:22.04
RUN apt-get update
USER appuser
CMD ["/bin/bash"]