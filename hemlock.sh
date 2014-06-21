#!/bin/bash

# BASED OFF THE GUIDE FROM:
# https://www.digitalocean.com/community/tutorials/how-to-use-logstash-and-kibana-to-centralize-and-visualize-logs-on-ubuntu-14-04

# Get Updates
apt-get updates
apt-get -y upgrade

# Install SSH
apt-get -y install ssh

# Add PPA Prereqs
apt-get -y install python-software-properties
apt-get -y install software-properties-common

# Add the Oracle Java PPA to apt:
add-apt-repository -y ppa:webupd8team/java

# Update your apt package database
apt-get update

# Install the latest stable version of Oracle Java 7 with this command 
echo debconf shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections
echo debconf shared/accepted-oracle-license-v1-1 seen true | sudo debconf-set-selections
apt-get -y install oracle-java7-installer

# Import the Elasticsearch public GPG key into apt
wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -

# Create the Elasticsearch source list
echo 'deb http://packages.elasticsearch.org/elasticsearch/1.1/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list

# Update your apt package database
apt-get update

# Install Elasticsearch 1.1.1 with this command
apt-get -y install elasticsearch=1.1.1

# Elasticsearch is now installed. The default configuration will work fine for our purposes, so let's start it now
service elasticsearch start

# Then run the following command to start Elasticsearch on boot up
update-rc.d elasticsearch defaults 95 10

# Install Kibana
cd ~; wget http://download.elasticsearch.org/kibana/kibana/kibana-latest.zip

# Install unzip so you can extract the kibana archive
apt-get -y install unzip

# Extract Kibana archive with unzip
unzip kibana-latest.zip

# In the Kibana configuration file, find the line that specifies the elasticsearch, and replace the port number (9200 by default) with 80
sed -i 's\elasticsearch: "http://"+window.location.hostname+":9200",\elasticsearch: "http://"+window.location.hostname+":80",\g' ~/kibana-latest/config.js

# We will be using Nginx to serve our Kibana installation, so let's move the files into an appropriate location. 
mkdir -p /var/www/kibana

# Now copy the Kibana files into your newly-created directory
cp -R ~/kibana-latest/* /var/www/kibana/

# Use apt to install Nginx
apt-get -y install nginx

# Download the sample Nginx configuration from Kibana's github repository to your home directory
cd ~; wget https://github.com/elasticsearch/kibana/raw/master/sample/nginx.conf

# Change the values of the server_name to your FQDN (or localhost if you aren't using a domain name) and root to where we installed Kibana
sed -i 's\kibana.myhost.org;\localhost;\g' nginx.conf
sed -i 's\root  /usr/share/kibana3;\root  /var/www/kibana;\g' nginx.conf

# Now copy it over your Nginx default server block
cp nginx.conf /etc/nginx/sites-available/default

# Now restart Nginx to put our changes into effect
service nginx restart

# Install LogStash
echo 'deb http://packages.elasticsearch.org/logstash/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list

# Update your apt package database
apt-get update

# Install Logstash 1.4.1
apt-get -y install logstash=1.4.1-1-bd507eb

# Generate SSL Certs directories
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private

# generate the SSL certificate and private key
cd /etc/pki/tls; sudo openssl req -x509 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt

# Let's create a configuration file called 10-syslog.conf and set up our "lumberjack" input 
echo "input {" >> /etc/logstash/conf.d/10-syslog.conf
echo "  lumberjack {" >> /etc/logstash/conf.d/10-syslog.conf
echo "    port => 5000" >> /etc/logstash/conf.d/10-syslog.conf
echo "    type => \"logs\"" >> /etc/logstash/conf.d/10-syslog.conf
echo "    ssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"" >> /etc/logstash/conf.d/10-syslog.conf
echo "    ssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"" >> /etc/logstash/conf.d/10-syslog.conf
echo "  }" >> /etc/logstash/conf.d/10-syslog.conf
echo "}" >> /etc/logstash/conf.d/10-syslog.conf
echo "" >> /etc/logstash/conf.d/10-syslog.conf
echo "filter {" >> /etc/logstash/conf.d/10-syslog.conf
echo "  if [type] == \"syslog\" {" >> /etc/logstash/conf.d/10-syslog.conf
echo "    grok {" >> /etc/logstash/conf.d/10-syslog.conf
echo "      match => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}\" }" >> /etc/logstash/conf.d/10-syslog.conf
echo "      add_field => [ \"received_at\", \"%{@timestamp}\" ]" >> /etc/logstash/conf.d/10-syslog.conf
echo "      add_field => [ \"received_from\", \"%{host}\" ]" >> /etc/logstash/conf.d/10-syslog.conf
echo "    }" >> /etc/logstash/conf.d/10-syslog.conf
echo "    syslog_pri { }" >> /etc/logstash/conf.d/10-syslog.conf
echo "    date {" >> /etc/logstash/conf.d/10-syslog.conf
echo "      match => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ]" >> /etc/logstash/conf.d/10-syslog.conf
echo "    }" >> /etc/logstash/conf.d/10-syslog.conf
echo "  }" >> /etc/logstash/conf.d/10-syslog.conf
echo "}" >> /etc/logstash/conf.d/10-syslog.conf
echo "" >> /etc/logstash/conf.d/10-syslog.conf
echo "output {" >> /etc/logstash/conf.d/10-syslog.conf
echo "  elasticsearch { host => localhost }" >> /etc/logstash/conf.d/10-syslog.conf
echo "  stdout { codec => rubydebug }" >> /etc/logstash/conf.d/10-syslog.conf
echo "}" >> /etc/logstash/conf.d/10-syslog.conf

# Restart Logstash
service logstash restart

apt-add-repository -y ppa:duh/golang
apt-get update
apt-get -y install golang
apt-get -y install build-essential git ruby ruby-dev
git clone git://github.com/elasticsearch/logstash-forwarder.git
cd logstash-forwarder
apt-get -y install rubygems
gem install fpm
umask 022
make deb