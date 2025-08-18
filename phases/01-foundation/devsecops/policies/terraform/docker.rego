package main
# Fail if any docker_container uses :latest (forces pinning)
deny[msg] {
  some name
  r := input.resource.docker_container[name]
  endswith(lower(r.image), ":latest")
  msg := sprintf("docker_container %s uses :latest tag in image %s", [name, r.image])
}
