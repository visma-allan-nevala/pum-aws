@echo off
IF NOT EXIST "%USERPROFILE%\.aws" md %USERPROFILE%\.aws
IF NOT EXIST "%USERPROFILE%\.pum-aws" type nul > %USERPROFILE%\.pum-aws
pushd "%~dp0"
docker build -t pum-aws .
docker run --rm -it -v %USERPROFILE%\.aws:/root/.aws -v %USERPROFILE%\.pum-aws:/root/.pum-aws pum-aws %*
popd