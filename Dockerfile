# Using ubuntu as a base image
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

## Installing the Dependencies for project
RUN apt-get update && apt-get install -y python3 python3-pip tzdata git nodejs npm wget jq
RUN pip3 install urllib3
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime && dpkg-reconfigure --frontend noninteractive tzdata

## Installing trivy
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.38.1/trivy_0.38.1_Linux-64bit.deb
RUN dpkg -i trivy_0.38.1_Linux-64bit.deb

# Clone the repository
RUN git clone https://github.com/girikMET/vuln_detections_cs602.git /vuln_detections_cs602

# Set the working directory inside the container
WORKDIR /vuln_detections_cs602

# Install dependencies
RUN npm install package.json

# Expose the required port
EXPOSE 3000

# Command to run the application
CMD ["node", "server.js"]