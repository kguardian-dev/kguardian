
# Prerequiste

sudo apt-get install libpq-dev
cargo install diesel_cli --no-default-features --features postgres

# local db set up first time
docker run \
    --name postgres-db \
    -p 5432:5432 \
    -e POSTGRES_USER=rust \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_DB=kube \
    -d postgres

    echo DATABASE_URL=postgres://rust@localhost/kube >.env

diesel setup

diesel migration generate pod_traffic

diesel print-schema > src/schema.rs

diesel_ext --model > src/models.rs

# Copy the sql statement to newly generated watcher folder in <>_pod-traffic

diesel migration run --config-file diesel.toml

## Helpful sql commands
```
sudo psql postgres://rust@localhost/kube
  \dt
  ```
