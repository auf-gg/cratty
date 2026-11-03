# Настоящий OpenSSH для проверки совместимости: тесты на russh::server проверяют
# нашу логику, но не то, как мы договариваемся с реализацией, к которой люди
# подключаются в жизни.
#
# vim и htop стоят здесь ради проверок M3: это программы полного экрана, и
# именно на них видно, работают ли альтернативный экран, атрибуты и цвета.
FROM alpine:3.21

# openssh-sftp-server — ради тестов передачи файлов: в Alpine он отдельным пакетом.
# AllowTcpForwarding — ради тестов проброса портов: в Alpine он выключен.
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
 # Каталог и файл, чтобы `ls --color` было чем раскрашивать.
 && mkdir -p /home/tester/каталог \
 && touch /home/tester/файл.txt \
 && chown -R tester:tester /home/tester

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
