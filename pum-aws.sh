#!/bin/sh
mkdir -p $HOME/.aws
touch $HOME/.pum-aws
docker build -t pum-aws .
docker run --rm -it -v $HOME/.aws:/root/.aws -v $HOME/.pum-aws:/root/.pum-aws pum-aws "$@"