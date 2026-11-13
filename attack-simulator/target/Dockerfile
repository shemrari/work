FROM amazonlinux:2023

RUN yum install -y openssh-server rsyslog && \
    yum clean all && \
    mkdir -p /var/log/ssh-lab /var/run/sshd && \
    touch /var/log/ssh-lab/secure

COPY sshd_config /etc/ssh/sshd_config
COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /usr/local/bin/ssh-lab-entrypoint
RUN chmod 0755 /usr/local/bin/ssh-lab-entrypoint

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/ssh-lab-entrypoint"]
