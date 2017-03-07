FROM centos:7

ENV DAQ_VERSION 2.0.6
ENV SNORT_VERSION 2.9.9.0

RUN yum -y install epel-release
RUN yum -y install \
 https://www.snort.org/downloads/archive/snort/daq-${DAQ_VERSION}-1.centos7.x86_64.rpm \
 https://www.snort.org/downloads/archive/snort/snort-openappid-${SNORT_VERSION}-1.centos7.x86_64.rpm

RUN ln -s /usr/lib64/snort-${SNORT_VERSION}_dynamicengine \
       /usr/local/lib/snort_dynamicengine && \
    ln -s /usr/lib64/snort-${SNORT_VERSION}_dynamicpreprocessor \
       /usr/local/lib/snort_dynamicpreprocessor

COPY etc /etc/snort
#COPY preproc_rules /etc/snort/preproc_rules
COPY rules /etc/snort/rules
#COPY so_rules /etc/snort/so_rules
COPY snort_socket.py .

#RUN mkdir /var/log/snort

# Cleanup.
#RUN yum clean all && \
#    rm -rf /var/log/* || true \
#    rm -rf /var/tmp/* \
#    rm -rf /tmp/*

RUN yum clean all

RUN /usr/sbin/snort -D -A unsock -c /etc/snort/simple_snort.conf
RUN nohup python snort_socket.py &

