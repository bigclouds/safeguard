# CUlinux-observer: KRSI(eBPF+LSM) based Linux security auditing tool

CUlinux-observer(CUOB) is a Linux audit and observer tool based on eBPF.
Security events can be audited and blocked based on the container of the process, and restrictions can be applied to container environments.

# Features

* Restriction rules based on process context, such as command name or UID and more
* Restrictions limited to containers
* Network Access Control
* File Access Control
* Restictions bind mounts from host filesystem to containers

# Build

```shell
$ git clone --recursive https://git.culinux.net/CULinux/CU-Observer.git && cd CU-Observer
# $ vagrant up && vagrant reload
# $ vagrant ssh

$ make libbpf-static
$ make build

sudo ./build/cu-observer --config config/example.yml |grep BLOCK
```



# LICENSE

CUOB's userspace program is licensed under MIT License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
