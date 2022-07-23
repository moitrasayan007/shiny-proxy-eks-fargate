FROM rocker/r-ver:3.6.3

RUN apt-get update && apt-get install -y \
    sudo \
    gdebi-core \
    pandoc \
    pandoc-citeproc \
    libcurl4-gnutls-dev \
    libcairo2-dev \
    libxt-dev \
    xtail \
    wget


# Add shiny user
RUN groupadd  shiny && \
    useradd --gid shiny --shell /bin/bash --create-home shiny


# Download and install ShinyServer
RUN wget --no-verbose https://download3.rstudio.org/ubuntu-14.04/x86_64/shiny-server-1.5.7.907-amd64.deb && \ 
    dpkg -i shiny-server-1.5.7.907-amd64.deb && \
    . /etc/environment && \
    R -e "install.packages(c('shiny', 'tidyverse','shinydashboard', 'xgboost', 'DT', 'plotly', 'tidymodels', 'ggridges', 'tidytext', 'rmarkdown'), repos='$MRAN')" && \
    cp -R /usr/local/lib/R/site-library/shiny/examples/* /srv/shiny-server/ && \
    chown shiny:shiny /var/lib/shiny-server

EXPOSE 3838

COPY shiny-server.sh /usr/bin/shiny-server.sh

RUN ["chmod", "+x", "/usr/bin/shiny-server.sh"]

CMD ["/usr/bin/shiny-server.sh"]