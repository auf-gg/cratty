# Real OpenSSH for compatibility checks: tests on russh::server verify
# our logic, but not how we negotiate with the implementation people
# actually connect to.
#
# vim and htop are here for the M3 checks: they are full-screen programs, and
# they show whether the alternate screen, attributes and colors work.
FROM alpine:3.21

# openssh-sftp-server — for the file transfer tests: it is a separate package in Alpine.
# AllowTcpForwarding — for the port forwarding tests: it is disabled in Alpine.
RUN apk add --no-cache openssh-server openssh-sftp-server vim htop ncurses \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:s3cret' | chpasswd \
 && printf '%s\n' \
      'PasswordAuthentication yes' \
      'PermitRootLogin no' \
      'PermitEmptyPasswords no' \
      'PrintMotd no'       'AllowTcpForwarding yes' \
      > /etc/ssh/sshd_config.d/cratty-test.conf \
 # A directory and a file so `ls --color` has something to color.
 && mkdir -p /home/tester/folder \
 && touch /home/tester/file.txt \
 && chown -R tester:tester /home/tester

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
