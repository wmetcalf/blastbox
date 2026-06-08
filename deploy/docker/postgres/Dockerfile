# Custom Postgres image with evirma/pg_bktree compiled in — gives us a
# SP-GiST BK-tree index on int8 for fast Hamming-distance queries on
# perceptual hashes. Upstream says "fixed to build with Postgresql 15";
# builds clean on 16 against the matching postgresql16-dev headers.
FROM postgres:16-alpine AS build
RUN apk add --no-cache git make gcc musl-dev libc-dev postgresql16-dev
# with_llvm=no skips the optional JIT bitcode build, which wants a specific
# clang version the alpine base doesn't ship. The .so is what Postgres
# actually loads at CREATE EXTENSION time.
RUN git clone --depth=1 https://github.com/evirma/pg_bktree.git /src \
 && cd /src \
 && make USE_PGXS=1 with_llvm=no \
 && make USE_PGXS=1 with_llvm=no install \
 && ls /usr/local/lib/postgresql/*.so /usr/local/share/postgresql/extension/bktree*

FROM postgres:16-alpine
COPY --from=build /usr/local/lib/postgresql/bktree*.so /usr/local/lib/postgresql/
COPY --from=build /usr/local/share/postgresql/extension/bktree* /usr/local/share/postgresql/extension/
COPY init-bktree.sql /docker-entrypoint-initdb.d/01-bktree.sql
