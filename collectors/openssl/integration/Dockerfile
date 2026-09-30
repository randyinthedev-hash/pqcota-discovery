# openssl-collector 실물 통합 테스트 (S1·S3). 격리 실행 — teardown이 라벨로 정리.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl libssl3 python3 \
 && rm -rf /var/lib/apt/lists/*
COPY openssl-collector /usr/local/bin/openssl-collector
COPY run-inside.sh /run-inside.sh
CMD ["bash", "/run-inside.sh"]
