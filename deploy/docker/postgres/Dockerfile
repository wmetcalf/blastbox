# Custom Postgres image with evirma/pg_bktree compiled in — gives us a
# SP-GiST BK-tree index on int8 for fast Hamming-distance queries on
# perceptual hashes. Upstream says "fixed to build with Postgresql 15";
# builds clean on 16 against the matching postgresql16-dev headers.
FROM postgres:16-alpine AS build
RUN apk add --no-cache git make gcc musl-dev libc-dev postgresql16-dev
# with_llvm=no skips the optional JIT bitcode build, which wants a specific
# clang version the alpine base doesn't ship. The .so is what Postgres
# actually loads at CREATE EXTENSION time.
# Pin to a specific commit (not HEAD) for a reproducible, tamper-evident build
# (mirrors the RedTusk postgres image). CREATE EXTENSION loads this .so as in-process
# Postgres native code with the DB's privileges, so an upstream force-push / compromise
# must NOT be pulled into the next rebuild unverified.
ARG PG_BKTREE_SHA=59db54ff5cd0b9f1b60c95be6f04414282699237
RUN git clone https://github.com/evirma/pg_bktree.git /src \
 && cd /src \
 && git -c advice.detachedHead=false checkout "${PG_BKTREE_SHA}" \
 && make USE_PGXS=1 with_llvm=no \
 && make USE_PGXS=1 with_llvm=no install \
 && ls /usr/local/lib/postgresql/*.so /usr/local/share/postgresql/extension/bktree*

FROM postgres:16-alpine
COPY --from=build /usr/local/lib/postgresql/bktree*.so /usr/local/lib/postgresql/
COPY --from=build /usr/local/share/postgresql/extension/bktree* /usr/local/share/postgresql/extension/
COPY init-bktree.sql /docker-entrypoint-initdb.d/01-bktree.sql
