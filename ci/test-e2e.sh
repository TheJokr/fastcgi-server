#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir e2e-logs

echo '::group::Install webservers'
sudo -n apt-get -qy update
sudo -n apt-get -qy install --no-install-recommends nginx-core apache2 lighttpd
echo '::endgroup::'

echo '::group::Build FastCGI examples'
cargo build --locked --examples --all-features
echo -e '::endgroup::\n'

declare -A servers=(
    [nginx]="nginx -c ${PWD}/ci/nginx.conf"
    [apache2]="apache2 -d ci -f apache2.conf -D FOREGROUND"
    [lighttpd]="lighttpd -f ci/lighttpd.conf -D"
)
for srv in "${!servers[@]}"; do
    echo "::group::Test with ${srv}"
    RUST_LOG=trace target/debug/examples/hello-cgi 2> "e2e-logs/hello-cgi-${srv}.log" &
    fcgi_pid="$!"

    ${servers["$srv"]} 2> "e2e-logs/${srv}.log" &
    newman run ci/e2e.postman_collection --env-var 'base_url=localhost:8080' \
        --color on --timeout 600000

    kill $(cat "/tmp/${srv}-ci.pid") "$fcgi_pid"
    wait -f
    echo '::endgroup::'

    # Avoid spurious socket errors between different servers
    sleep 2s
done
